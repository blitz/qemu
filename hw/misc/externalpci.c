/**
 * PCI devices implemented by external processes.
 *
 * Copyright (C) 2013, Julian Stecklina <jsteckli@os.inf.tu-dresden.de>
 * Economic rights: Technische Universitaet Dresden (Germany)
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */


#include "hw/hw.h"
#include "hw/pci/pci.h"
#include "sysemu/dma.h"
#include "hw/loader.h"
#include "sysemu/sysemu.h"
#include "exec/cpu-all.h"
#include "hw/pci/msix.h"
#include "hw/pci/msi.h"
#include "sysemu/kvm.h"

#include "hw/misc/externalpci.h"

#include <iso646.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/eventfd.h>
#include <sys/un.h>

typedef struct ExternalPCIBAR {
  struct ExternalPCI *parent;
  MemoryRegion        region;
  EventNotifier       notifier;
} ExternalPCIBAR;

typedef struct ExternalPCI {
  PCIDevice   pdev;
  char       *socket_path;
  int         socket;

  uint16_t vendor_id;
  uint16_t device_id;

  ExternalPCIBAR bar[6];
  unsigned char msix_bar;

} ExternalPCI;

#define LOG(str, ...) fprintf(stderr, "%-20s | " str "\n", __func__, ## __VA_ARGS__)


/* Returns file descriptor on success, -1 otherwise. */
static int
domain_socket_connect(const char *addr)
{
  int                fd;
  struct sockaddr_un sa;

  fd = socket(PF_LOCAL, SOCK_SEQPACKET, 0);
  if (fd < 0) return -1;

  sa.sun_family = AF_LOCAL;
  strncpy(sa.sun_path, addr, sizeof(sa.sun_path));
  if (0 > connect(fd, (struct sockaddr *)(&sa), sizeof(sa))) {
    int oe = errno;
    close(fd);
    errno = oe;
    return -1;
  }
  
  return fd;
}

/* Returns zero on success. On failure, errno is set. */
static int
externalpci_call(int fd, externalpci_req *req, externalpci_res *res)
{
  struct msghdr   hdr;
  struct iovec    iov = { req, sizeof(*req) };
  char            chdr_data[CMSG_SPACE(sizeof(int))];
  struct cmsghdr *chdr = (struct cmsghdr *)chdr_data;

  hdr.msg_namelen = 0;
  hdr.msg_iov     = &iov;
  hdr.msg_iovlen  = 1;
  hdr.msg_flags   = 0;
  hdr.msg_control    = NULL;
  hdr.msg_controllen = 0;

  chdr->cmsg_len   = CMSG_LEN(sizeof(int));
  chdr->cmsg_level = SOL_SOCKET;
  chdr->cmsg_type  = SCM_RIGHTS;
    
  if (req->type == EXTERNALPCI_REQ_REGION or
      req->type == EXTERNALPCI_REQ_IRQ) {
    // Pass file descriptor
    hdr.msg_control    = chdr;
    hdr.msg_controllen = CMSG_LEN(sizeof(int));

    memcpy(CMSG_DATA(chdr),
	   (req->type == EXTERNALPCI_REQ_REGION) ? &req->region.fd : &req->irq_req.fd,
	   sizeof(int));
  }

  int err;
 send_again:
  err = sendmsg(fd, &hdr, MSG_EOR | MSG_NOSIGNAL);
  if (err != sizeof(*req)) {
    if (err < 0 && errno == EINTR) goto send_again;
    return -1;
  }

  iov.iov_base = res;
  iov.iov_len = sizeof(*res);
  hdr.msg_control    = chdr;
  hdr.msg_controllen = CMSG_SPACE(sizeof(int));

 recv_again:
  err = recvmsg(fd, &hdr, 0);
  if (err != sizeof(*res)) {
    if (err < 0 && errno == EINTR) goto recv_again;
    return -1;
  }

  struct cmsghdr *incoming_chdr = CMSG_FIRSTHDR(&hdr);
  if (incoming_chdr) {
    int fd;
    memcpy(&fd, CMSG_DATA(chdr), sizeof(int));

    if (res->type == EXTERNALPCI_REQ_PCI_INFO) {
      res->pci_info.hotspot_fd = fd;
    } else {
      LOG("Received file descriptor, but didn't expect one.");
      close(fd);
    }
  }

  if (not incoming_chdr and res->type == EXTERNALPCI_REQ_PCI_INFO) {
    LOG("No hotspot?");
    res->pci_info.hotspot_fd = 0;
  }

  return 0;
}

static void
externalpci_query_irqs(ExternalPCI *d)
{
  /* XXX Destroy/cleanup old config. */

  LOG("Querying IRQs...");

  externalpci_req req = { .type = EXTERNALPCI_REQ_IRQ,
                          .irq_req = { .idx = 0 } };
  externalpci_res res;
  
  do {
    req.irq_req.fd = eventfd(0, 0);
    int err = externalpci_call(d->socket, &req, &res);
    if (err) { abort(); }

    if (not res.irq_res.valid) {
      close(req.irq_req.fd);
      goto next;
    }
    
    MSIMessage msg = msix_get_message(&d->pdev, req.irq_req.idx);
    int virq = kvm_irqchip_add_msi_route(kvm_state, msg);
    if (err < 0) { abort(); }

    LOG("MSI-X vector %u -> IRQ %u", req.irq_req.idx, virq);

    EventNotifier n;
    event_notifier_init_fd(&n, req.irq_req.fd);

    err = kvm_irqchip_add_irqfd_notifier(kvm_state, &n, virq);
    if (err < 0) { abort(); }

  next:
    req.irq_req.idx ++;
  } while (res.irq_res.more);

  int idx = req.irq_req.idx;
  LOG("Querying %u vector%s complete.", idx, idx == 1 ? "" : "s");
}

static uint64_t
externalpci_io_read(void *opaque,
		    hwaddr addr,
		    unsigned size)
{
  ExternalPCIBAR *bar    = opaque;
  ExternalPCI    *d      = bar->parent;
  unsigned        bar_no = bar - &d->bar[0];

  externalpci_req req = { .type = EXTERNALPCI_REQ_IOT };
  req.iot_req.hwaddr = addr;
  req.iot_req.size   = size;
  req.iot_req.bar    = bar_no;
  req.iot_req.type   = IOT_READ;


  externalpci_res res;
  int err = externalpci_call(d->socket, &req, &res);
  if (err) { abort(); }

  if (res.flags & EXTERNALPCI_RES_FLAG_FETCH_IRQS)
    externalpci_query_irqs(d);

  return res.iot_res.value;
}

static void
externalpci_io_write(void *opaque,
		     hwaddr addr,
		     uint64_t val,
		     unsigned size)
{

  ExternalPCIBAR *bar    = opaque;
  ExternalPCI    *d      = bar->parent;
  unsigned        bar_no = bar - &d->bar[0];

  externalpci_req req = { .type = EXTERNALPCI_REQ_IOT };
  req.iot_req.hwaddr = addr;
  req.iot_req.value  = val;
  req.iot_req.size   = size;
  req.iot_req.bar    = bar_no;
  req.iot_req.type   = IOT_WRITE;

  externalpci_res res;
  int err = externalpci_call(d->socket, &req, &res);
  if (err) { abort(); }

  if (res.flags & EXTERNALPCI_RES_FLAG_FETCH_IRQS)
    externalpci_query_irqs(d);
}


static const MemoryRegionOps externalpci_io_ops = {
    .read = externalpci_io_read,
    .write = externalpci_io_write,
    .impl = {
        .min_access_size = 1,
        .max_access_size = 4,
    },
    .endianness = DEVICE_LITTLE_ENDIAN,
};


static int externalpci_init(PCIDevice *pdev)
{
  ExternalPCI *d = DO_UPCAST(ExternalPCI, pdev, pdev);

  if (d->socket_path == 0) {
    LOG("Must provide socket= option.");
    return -1;
  }

  LOG("Establishing connection to %s.", d->socket_path);
  d->socket = domain_socket_connect(d->socket_path);
  if (d->socket < 0) {
    LOG("Error: %s", strerror(errno));
    return -1;
  }

  LOG("Mapping guest memory to remote end.");

  RAMBlock *block;
  qemu_mutex_lock_ramlist();
  QTAILQ_FOREACH(block, &ram_list.blocks, next) {
    externalpci_res res;
    externalpci_req req = { .type = EXTERNALPCI_REQ_REGION };

    LOG("region fd %2u offset %08lx len %08lx",
	block->fd, block->offset, block->length);
    
    req.region.fd        = block->fd;
    req.region.offset    = 0;
    req.region.phys_addr = block->offset;
    req.region.size      = block->length;

    if (externalpci_call(d->socket, &req, &res) != 0) {
      LOG("I/O error?");
      goto unlock_fail;
    }
    
  }
  qemu_mutex_unlock_ramlist();


  externalpci_req req = { .type = EXTERNALPCI_REQ_PCI_INFO };
  externalpci_res res;
  if (externalpci_call(d->socket, &req, &res) != 0) {
    LOG("I/O error?");
    return -1;
  }

  LOG("PCI ID: %04x:%04x", res.pci_info.vendor_id, res.pci_info.device_id);
  uint8_t *config = pdev->config;

  pci_set_word(config + PCI_VENDOR_ID, res.pci_info.vendor_id);
  pci_set_word(config + PCI_DEVICE_ID, res.pci_info.device_id);
  pci_set_word(config + PCI_SUBSYSTEM_VENDOR_ID, res.pci_info.subsystem_vendor_id);
  pci_set_word(config + PCI_SUBSYSTEM_ID, res.pci_info.subsystem_id);

  /* XXX Hardcode this to network devices for now. */
  pci_set_long(config + PCI_CLASS_REVISION, 0x02000000);

  config[PCI_INTERRUPT_PIN] = 1;

  LOG("Registering BARs...");
  unsigned bar_no;
  for (bar_no = 0; bar_no < 6; bar_no++) {
    uint32_t bar = res.pci_info.bar[bar_no].size;
    if (bar == 0) break;
    
    if ((bar & PCI_BASE_ADDRESS_SPACE) == PCI_BASE_ADDRESS_SPACE_IO) {
      ExternalPCIBAR *bar_data = &d->bar[bar_no];
      bar_data->parent = d;
      memory_region_init_io(&bar_data->region, &externalpci_io_ops, bar_data, "externalpci-io",
			    bar & PCI_BASE_ADDRESS_IO_MASK);
      pci_register_bar(pdev, bar_no, PCI_BASE_ADDRESS_SPACE_IO, &bar_data->region);
      LOG("BAR[%u]: IO %08lx", bar_no, bar & PCI_BASE_ADDRESS_IO_MASK);

      if (bar_no == res.pci_info.hotspot_bar) {
	event_notifier_init_fd(&bar_data->notifier, res.pci_info.hotspot_fd);
	memory_region_add_eventfd(&bar_data->region,
				  res.pci_info.hotspot_addr,
				  res.pci_info.hotspot_size,
				  false, 0,
				  &bar_data->notifier);
	LOG("Added notifier to hotspot %x+%x",
	    res.pci_info.hotspot_addr, res.pci_info.hotspot_size);
      }

    } else {
      LOG("XXX Skipping memory BAR.");
    }
  }

  if (bar_no == 6) {
    LOG("XXX Too many BARs to enable MSI-X.");
    return -1;
  }

  d->msix_bar = bar_no;
  int err = msix_init_exclusive_bar(pdev, res.pci_info.msix_vectors, d->msix_bar);
  if (err) { return err; }


  LOG("Looks good so far.");
  //qemu_set_fd_handler2(d->socket, 

  return 0;
 unlock_fail:
  qemu_mutex_unlock_ramlist();
  return -1;
}

/* static const MemoryRegionOps externalpci_mmio_ops = { */
/*     .read  = externalpci_read, */
/*     .write = externalpci_write, */
/*     .endianness = DEVICE_LITTLE_ENDIAN, */
/* }; */


static void externalpci_exit(PCIDevice *dev)
{
  LOG("Exit!");

  ExternalPCI *d = DO_UPCAST(ExternalPCI, pdev, dev);
  externalpci_req req = { .type = EXTERNALPCI_REQ_EXIT };
  externalpci_res res;
  if (externalpci_call(d->socket, &req, &res) != 0) {
    abort();
  }
}

static void externalpci_reset(DeviceState *dev)
{
  LOG("Reset!");

  ExternalPCI *d = DO_UPCAST(ExternalPCI, pdev.qdev, dev);
  externalpci_req req = { .type = EXTERNALPCI_REQ_RESET };
  externalpci_res res;
  if (externalpci_call(d->socket, &req, &res) != 0) {
    abort();
  }
}

static Property externalpci_properties[] = {
  DEFINE_PROP_STRING("socket", ExternalPCI, socket_path),
  DEFINE_PROP_END_OF_LIST(),
};

static void externalpci_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    PCIDeviceClass *k = PCI_DEVICE_CLASS(klass);

    k->init = externalpci_init;
    k->exit = externalpci_exit;

    k->vendor_id = 0xDEAD;
    k->device_id = 0xBEEF;

    dc->reset = externalpci_reset;
    dc->props = externalpci_properties;
}

static const TypeInfo externalpci_info = {
    .name          = "externalpci",
    .parent        = TYPE_PCI_DEVICE,
    .instance_size = sizeof(ExternalPCI),
    .class_init    = externalpci_class_init,
};

static void externalpci_register_types(void)
{
    type_register_static(&externalpci_info);
}

type_init(externalpci_register_types)
