#include <assert.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include <inttypes.h>
#include <iso646.h>

#include "common.h"
#include "util.h"
#include "virtio-constants.h"
#include "iov.h"

/* Private data structures. */

#define VIRTQUEUE_MAX_SIZE 1024
typedef struct VirtQueueElement
{
    unsigned int index;
    unsigned int out_num;
    unsigned int in_num;
    hwaddr in_addr[VIRTQUEUE_MAX_SIZE];
    hwaddr out_addr[VIRTQUEUE_MAX_SIZE];
    struct iovec in_sg[VIRTQUEUE_MAX_SIZE];
    struct iovec out_sg[VIRTQUEUE_MAX_SIZE];
} VirtQueueElement;

typedef struct VRingDesc
{
    uint64_t addr;
    uint32_t len;
    uint16_t flags;
    uint16_t next;
} VRingDesc;

typedef struct VRingAvail
{
    uint16_t flags;
    uint16_t idx;
    uint16_t ring[0];
} VRingAvail;

typedef struct VRingUsedElem
{
    uint32_t id;
    uint32_t len;
} VRingUsedElem;

typedef struct VRingUsed
{
    uint16_t flags;
    uint16_t idx;
    VRingUsedElem ring[0];
} VRingUsed;

typedef struct VRing
{
    unsigned int num;
    VRingDesc  *desc;
    VRingAvail *avail;
    VRingUsed  *used;
} VRing;

struct VirtQueue
{
  struct device_state *state;

  VRing vring;
  hwaddr pa;
  uint16_t last_avail_idx;
  /* Last used index value we have signalled on */
  uint16_t signalled_used;

  /* Last used index value we have signalled on */
  bool signalled_used_valid;

  /* Notification enabled? */
  bool notification;
  uint16_t queue_index;

  int inuse;

  uint16_t vector;
  // void (*handle_output)(VirtIODevice *vdev, VirtQueue *vq);

  // EventNotifier guest_notifier;
  // EventNotifier host_notifier;
};

/* Virtio implementation */

VirtQueue *vnet_add_queue(struct device_state *state, int queue_size)
{
    int i;

    for (i = 0; i < VIRTIO_PCI_QUEUE_MAX; i++)
	if (state->vq[i].vring.num == 0)
	    break;

    if (i == VIRTIO_PCI_QUEUE_MAX || queue_size > VIRTQUEUE_MAX_SIZE)
	abort();

    state->vq[i].vring.num = queue_size;
    //state->vq[i].handle_output = handle_output;

    return &state->vq[i];
}


void vnet_init(struct device_state *state, externalpci_pci_info_res *res)
{
  LOG(state, "Replying with device details.");
  res->vendor_id = VIRTIO_NET_VENDOR_ID;
  res->device_id = VIRTIO_NET_DEVICE_ID;

  res->subsystem_vendor_id = VIRTIO_NET_SUBSYSTEM_VENDOR_ID;
  res->subsystem_id = VIRTIO_NET_SUBSYSTEM_ID;

  res->bar[0].size = 0x40 | PCI_BASE_ADDRESS_SPACE_IO;
  res->msix_vectors = 3;
}

void vnet_irq_info(struct device_state *state, int fd, int msix_idx, externalpci_irq_res *res)
{
  if (state->irqs[msix_idx].fd == 0) {
    state->irqs[msix_idx].fd = fd;
    LOG(state, "MSI-X vector %u triggered by fd %u.", msix_idx, fd);
    res->valid = true;
  } else {
    /* Already configured */
    close(fd);
    res->valid = false;
  }

  res->more = ((msix_idx + 1) < MAX_MSIX_VECTORS);
}

static hwaddr vnet_queue_get_addr(struct device_state *state,
				  unsigned queue)
{
  return state->vq[queue].pa;
}

static inline void *vnet_vring_align(void *addr,
				      unsigned long align)
{
  return (void *)(((uintptr_t)addr + align - 1) & ~(align - 1));
}

static void vnet_queue_set_addr(struct device_state *state,
				  unsigned queue, hwaddr addr)
{
  VirtQueue *vq = &state->vq[queue];

  vq->pa = addr;

  char *va = translate_pointer(state, vq->pa, 4096 /* XXX */);

  vq->vring.desc  = (VRingDesc *)va;
  vq->vring.avail = (VRingAvail *)(va + vq->vring.num * sizeof(VRingDesc));
  vq->vring.used  = (VRingUsed *)vnet_vring_align((char *)vq->vring.avail +
						  offsetof(VRingAvail, ring[vq->vring.num]),
						  VIRTIO_PCI_VRING_ALIGN);

  LOG(state, "Queue %u mapped at:", queue);
  LOG(state, "\tdesc  %p", vq->vring.desc);
  LOG(state, "\tavail %p", vq->vring.avail);
  LOG(state, "\tused  %p", vq->vring.used);

}

static unsigned vnet_queue_get_num(struct device_state *state,
				   unsigned queue)
{
  if (queue >= VIRTIO_PCI_QUEUE_MAX) {
    LOG(state, "Guest selected non-existent queue %u.\n", queue);
    return 0;
  }

  return state->vq[queue].vring.num;
}

uint64_t vnet_io_read(struct device_state *state, unsigned bar, uint64_t addr,
		      unsigned size)
{
  assert(bar == 0);
  (void)size;                   /* We don't care. */

  uint32_t ret = 0xFFFFFFFF;

  switch (addr) {
  case VIRTIO_PCI_HOST_FEATURES:
    ret = state->host_features;
    break;
  case VIRTIO_PCI_GUEST_FEATURES:
    ret = state->guest_features;
    break;
  case VIRTIO_PCI_QUEUE_PFN:
    ret = vnet_queue_get_addr(state, state->queue_sel)
      >> VIRTIO_PCI_QUEUE_ADDR_SHIFT;
    break;
  case VIRTIO_PCI_QUEUE_NUM:
    ret = vnet_queue_get_num(state, state->queue_sel);
    break;
  case VIRTIO_PCI_QUEUE_SEL:
    ret = state->queue_sel;
    break;
  case VIRTIO_PCI_STATUS:
    ret = state->status;
    break;
  case VIRTIO_PCI_ISR:
    /* reading from the ISR also clears it. */
    ret = state->isr;
    state->isr = 0;
    LOG(state, "VIRTIO_PCI_ISR XXX");
    //qemu_set_irq(proxy->pci_dev.irq[0], 0);
    break;
  case VIRTIO_MSI_CONFIG_VECTOR:
    //ret = state->config_vector;
    LOG(state, "XXX MSI_CONFIG_VECTOR");
    ret = 0;
    break;
  case VIRTIO_MSI_QUEUE_VECTOR:
    ret = state->vq[state->queue_sel].vector;
    break;
  default:
    break;
  }

  return ret;
}

static void
vnet_set_status(struct device_state *state, uint8_t val)
{
  /* XXX Do more? see virtio_net_set_status */
  state->status = val;
}

static inline void
vnet_set_notification(struct VirtQueue *vq,
		      bool enable)
{
  // XXX Support for VIRTIO_RING_F_EVENT_IDX

  if (enable) {
    __atomic_and_fetch(&vq->vring.used->flags, ~VRING_USED_F_NO_NOTIFY,
		       __ATOMIC_RELEASE);
  } else {
    // XXX Probably overkill to use an atomic access here.
    __atomic_or_fetch(&vq->vring.used->flags, VRING_USED_F_NO_NOTIFY,
		      __ATOMIC_RELEASE);
  }
}

static unsigned int
vnet_virtqueue_get_head(VirtQueue *vq, unsigned int idx)
{
    unsigned int head;

    /* Grab the next descriptor number they're advertising, and increment
     * the index we've seen. */
    head = __atomic_load_n(&vq->vring.avail->ring[idx % vq->vring.num],
			   __ATOMIC_ACQUIRE);

    /* If their number is silly, that's a fatal mistake. */
    assert(head < vq->vring.num);

    return head;
}


static int
vnet_virtqueue_num_heads(VirtQueue *vq, unsigned int idx)
{
  /* Callers read a descriptor at vq->last_avail_idx.  Make sure
   * descriptor read does not bypass avail index read. */
  uint16_t num_heads = __atomic_load_n(&vq->vring.avail->idx,
				       __ATOMIC_ACQUIRE) - idx;

  /* Check it isn't doing very strange things with descriptor numbers. */
  assert(num_heads <= vq->vring.num);

  return num_heads;
}

static unsigned
vnet_virtqueue_next_desc(VRingDesc *desc, unsigned int max)
{
    unsigned int next;

    /* If this descriptor says it doesn't chain, we're done. */
    if (!(desc->flags & VRING_DESC_F_NEXT))
	return max;

    /* Check they're not leading us off end of descriptors. */
    next = __atomic_load_n(&desc->next, __ATOMIC_ACQUIRE);

    assert(next < max);

    return next;
}

void vnet_virtqueue_map_sg(struct device_state *state,
			   struct iovec *sg, hwaddr *addr,
			   size_t num_sg)
{
    unsigned int i;
    hwaddr len;

    for (i = 0; i < num_sg; i++) {
	len = sg[i].iov_len;
	sg[i].iov_base = translate_pointer(state, addr[i], len);
	assert(sg[i].iov_base != NULL);
    }
}

static int
vnet_virtqueue_pop(VirtQueue *vq, VirtQueueElement *elem)
{
    unsigned int i, head, max;
    VRingDesc *desc = vq->vring.desc;

    if (!vnet_virtqueue_num_heads(vq, vq->last_avail_idx))
	return 0;

    /* When we start there are none of either input nor output. */
    elem->out_num = elem->in_num = 0;

    max = vq->vring.num;

    i = head = vnet_virtqueue_get_head(vq, vq->last_avail_idx++);
    // if (vq->vdev->guest_features & (1 << VIRTIO_RING_F_EVENT_IDX)) {
    //     vring_avail_event(vq, vring_avail_idx(vq));
    // }

    if (desc[i].flags & VRING_DESC_F_INDIRECT) {
      assert(desc[i].len % sizeof(VRingDesc) == 0);

      /* loop over the indirect descriptor table */
      max = desc[i].len / sizeof(VRingDesc);
      desc = translate_pointer(vq->state, desc[i].addr, 4096 /* ??? */);
      assert(desc != NULL);
      i = 0;
    }

    /* Collect all the descriptors */
    do {
	struct iovec *sg;

	if (desc[i].flags & VRING_DESC_F_WRITE) {
	  // Too many write descriptors in indirect table?
	  assert(elem->in_num < ARRAY_SIZE(elem->in_sg));

	  elem->in_addr[elem->in_num] = desc[i].addr;
	  sg = &elem->in_sg[elem->in_num++];
	} else {
	  assert(elem->out_num < ARRAY_SIZE(elem->out_sg));

	  elem->out_addr[elem->out_num] = desc[i].addr;
	  sg = &elem->out_sg[elem->out_num++];
	}

	sg->iov_len = desc[i].len;

	/* If we've got too many, that implies a descriptor loop. */
	assert((elem->in_num + elem->out_num) <= max);
    } while ((i = vnet_virtqueue_next_desc(&desc[i], max)) != max);

    /* Now map what we have collected */
    vnet_virtqueue_map_sg(vq->state, elem->in_sg, elem->in_addr, elem->in_num);
    vnet_virtqueue_map_sg(vq->state, elem->out_sg, elem->out_addr, elem->out_num);

    elem->index = head;

    vq->inuse++;

    return elem->in_num + elem->out_num;
}

static void
vnet_virtqueue_fill(VirtQueue *vq, const VirtQueueElement *elem,
		    unsigned int len, unsigned int idx)
{
    /* XXX In the original qemu code this function marks the memory
       pointed to by the scatter gather lists as dirty. */

    idx = (idx + vq->vring.used->idx) % vq->vring.num;

    /* Get a pointer to the next entry in the used ring. */
    VRingUsedElem *el = &vq->vring.used->ring[idx];
    el->id  = elem->index;
    el->len = len;
}


static void
vnet_virtqueue_flush(VirtQueue *vq, unsigned int count)
{
    uint16_t old, new;
    VRingUsed *used = vq->vring.used;
    old = __atomic_load_n(&used->idx, __ATOMIC_ACQUIRE);
    new = old + count;
    __atomic_store_n(&used->idx, new, __ATOMIC_RELEASE);
    vq->inuse -= count;

    if (unlikely((int16_t)(new - vq->signalled_used) < (uint16_t)(new - old)))
	vq->signalled_used_valid = false;
}


static void vnet_virtqueue_push(VirtQueue *vq,
				const VirtQueueElement *elem,
				unsigned int len)
{

  vnet_virtqueue_fill(vq, elem, len, 0);
  vnet_virtqueue_flush(vq, 1);
}

/* Assuming a given event_idx value from the other size, if
 * we have just incremented index from old to new_idx,
 * should we trigger an event? */
static inline int
vnet_vring_need_event(uint16_t event, uint16_t new, uint16_t old)
{
  /* Note: Xen has similar logic for notification hold-off
   * in include/xen/interface/io/ring.h with req_event and req_prod
   * corresponding to event_idx + 1 and new respectively.
   * Note also that req_event and req_prod in Xen start at 1,
   * event indexes in virtio start at 0. */
  return (uint16_t)(new - event - 1) < (uint16_t)(new - old);
}


/* Do we need to notify the guest? */
static bool
vnet_vring_notify(VirtQueue *vq)
{
    uint16_t old, new;
    bool v;

    uint32_t guest_features = vq->state->guest_features;

    /* We need to expose used array entries before checking used event. */
    unsigned avail_idx = __atomic_load_n(&vq->vring.avail->idx, __ATOMIC_SEQ_CST);

    /* Always notify when queue is empty (when feature acknowledge) */
    if (((guest_features & (1 << VIRTIO_F_NOTIFY_ON_EMPTY)) &&
	 !vq->inuse && avail_idx == vq->last_avail_idx)) {
	return true;
    }

    if (!(guest_features & (1 << VIRTIO_RING_F_EVENT_IDX))) {
	return !(vq->vring.avail->flags & VRING_AVAIL_F_NO_INTERRUPT);
    }

    v = vq->signalled_used_valid;
    vq->signalled_used_valid = true;
    old = vq->signalled_used;
    new = vq->signalled_used = vq->vring.used->idx;

    /* XXX Is this correct? */
    return !v || vnet_vring_need_event(vq->vring.avail->ring[vq->vring.num], new, old);
}

static void
vnet_send_notify(VirtQueue *vq)
{
  if (vnet_vring_notify(vq)) {
    __atomic_store_n(&vq->state->isr, 1, __ATOMIC_RELEASE);

    int msix_idx = vq->vector;
    if (msix_idx == VIRTIO_MSI_NO_VECTOR) {
      LOG(vq->state, "No MSI-X vector configured!");
      return;
    }

    uint64_t v = 1;
    int fd = vq->state->irqs[msix_idx].fd;

    LOG(vq->state, "Trigger MSI-X vector %u via fd %d!", msix_idx, fd);
    if (fd)
      write(fd, &v, sizeof(v));
  }
}

static size_t
vnet_hdr_size(struct device_state *state)
{
  return (state->guest_features & (1 << VIRTIO_NET_F_MRG_RXBUF)) ?
    sizeof(struct virtio_net_hdr_mrg_rxbuf) :
    sizeof(struct virtio_net_hdr);
}

static bool
vnet_poll_tx(struct device_state *state)
{
  VirtQueue *vq               = &state->vq[1];
  bool       work_done        = false;
  size_t     expected_hdr_len = vnet_hdr_size(state);

  if (not vq->pa or not (state->status & VIRTIO_CONFIG_S_DRIVER_OK)) {
    LOG(state, "Driver not ready!");
    return false;
  }

  VirtQueueElement elem;
  while (vnet_virtqueue_pop(vq, &elem)) {

    LOG(state, "TX %zu bytes out.", iov_size(elem.out_sg, elem.out_num));

    assert(elem.out_num > 1);
    assert(elem.out_sg[0].iov_len == expected_hdr_len);
    struct virtio_net_hdr *hdr = elem.out_sg[0].iov_base;

    /* Header seems to be empty? */

    LOG(state, "TX flags %x hdr_len %x gso_type %x gso_size %x csum_start %x csum_offset %x",
	hdr->flags, hdr->hdr_len, hdr->gso_type,
	hdr->gso_size, hdr->csum_start, hdr->csum_offset);

    packet_out(state, elem.out_sg, elem.out_num, expected_hdr_len);

    vnet_virtqueue_push(vq, &elem, 0);
    vnet_send_notify(vq);
    work_done = true;
  }

  // Reenable notifications, if we haven't seen any packets.
  if (not work_done)
    vnet_set_notification(vq, true);

  return work_done;
}

bool
vnet_poll(struct device_state *state)
{
  /* TX */
  bool work_done = false;

  work_done =
    vnet_poll_tx(state)
    // | vnet_poll_ctrl(state)
    ;

  return work_done;
}

static void
vnet_packet_in(struct device_state *state,
	       struct iovec *iov, unsigned len,
	       size_t hdr_offset)
{
  LOG(state, "Received %zu bytes packet.", iov_size(iov, len) - hdr_offset);

  VirtQueue *vq               = &state->vq[0];
  size_t     expected_hdr_len = vnet_hdr_size(state);
  assert(expected_hdr_len == hdr_offset);

  if (not vq->pa
      or not (state->status & VIRTIO_CONFIG_S_DRIVER_OK)
      or vq->vring.avail->idx == 0) {
    LOG(state, "Driver not ready!");
    return;
  }

  VirtQueueElement elem;
  if (vnet_virtqueue_pop(vq, &elem) == 0) {
    /* No room in queue. Drop packet. */
    return;
  }

  iov_move(elem.in_sg, elem.in_num,
	   iov, len,
	   0);

  vnet_virtqueue_push(vq, &elem, iov_size(elem.in_sg, elem.in_num));
  vnet_send_notify(vq);
}

void
vnet_reset(struct device_state *state)
{
  LOG(state, "Reset!");
  vnet_set_status(state, 0);

  /* XXX virtio_net_reset ? */

  state->guest_features = 0;
  state->queue_sel = 0;
  state->status = 0;
  state->isr = 0;
  state->config_vector = VIRTIO_MSI_NO_VECTOR;
  //virtio_notify_vector(state, state->config_vector);

  if (state->vq == 0)
    state->vq = calloc(VIRTIO_PCI_QUEUE_MAX, sizeof(VirtQueue));

  for(unsigned i = 0; i < VIRTIO_PCI_QUEUE_MAX; i++) {
    state->vq[i].state = state;
    state->vq[i].vring.desc = 0;
    state->vq[i].vring.avail = 0;
    state->vq[i].vring.used = 0;
    state->vq[i].last_avail_idx = 0;
    state->vq[i].pa = 0;
    state->vq[i].vector = VIRTIO_MSI_NO_VECTOR;
    state->vq[i].signalled_used = 0;
    state->vq[i].signalled_used_valid = false;
    state->vq[i].notification = true;
  }

  vnet_add_queue(state, 256 /*, handle_rx */);
  vnet_add_queue(state, 256 /*, handle_tx */);
  vnet_add_queue(state, 256 /*, handle_ctrl */);

  state->packet_in = vnet_packet_in;
}

static void vnet_queue_notify(struct device_state *state, unsigned queue)
{
  LOG(state, "Ping queue %u.", queue);
  // XXX Check whether we have valid pointers in the vq.
  vnet_set_notification(&state->vq[queue], false);
  schedule_poll(state);
}

void vnet_io_write(struct device_state *state, unsigned bar, uint64_t addr,
		   unsigned size, uint64_t val)
{
  assert(bar == 0);
  (void)size;                   /* We don't care. */

  switch (addr) {
  case VIRTIO_PCI_QUEUE_NOTIFY:
    if (val >= VIRTIO_PCI_QUEUE_MAX) {
      LOG(state, "Guest notified non-existent queue %u.", (unsigned)val);
      return;
    }
    vnet_queue_notify(state, val);
    break;
  case VIRTIO_PCI_QUEUE_SEL:
    if (val >= VIRTIO_PCI_QUEUE_MAX) {
      LOG(state, "Guest selected non-existent queue %u.", (unsigned)val);
      return;
    }
    LOG(state, "Guest selected queue %u.", (unsigned)val);
    state->queue_sel = val;
    break;
  case VIRTIO_PCI_QUEUE_PFN:
    vnet_queue_set_addr(state, state->queue_sel, val << VIRTIO_PCI_QUEUE_ADDR_SHIFT);
    break;
  case VIRTIO_PCI_GUEST_FEATURES:
    /* Guest does not negotiate properly?  We have to assume nothing. */
    if (val & (1 << VIRTIO_F_BAD_FEATURE)) {
      LOG(state, "BAD FEATURE set. Guest broken.");
    }

    uint32_t supported_features = 0; /* What do we support? */
    uint32_t bad = (val & ~supported_features) != 0;
    if (bad)
      LOG(state, "Guest has some unsupported features: %x.\n", bad);

    val &= supported_features;
    /* Propagate to network */
    LOG(state, "XXX set GUEST_FEATURES");
    state->guest_features = val;
    break;
  case VIRTIO_PCI_STATUS:
    if (!(val & VIRTIO_CONFIG_S_DRIVER_OK)) {
      // virtio_pci_stop_ioeventfd(proxy);
    }

    vnet_set_status(state, val & 0xFF);

    if (val & VIRTIO_CONFIG_S_DRIVER_OK) {
      // virtio_pci_start_ioeventfd(proxy);
    }

    if (state->status == 0) {
      // vnet_reset(state);
      // msix_unuse_all_vectors(&proxy->pci_dev);
    }
    break;
  case VIRTIO_MSI_CONFIG_VECTOR:
    LOG(state, "Configuration change vector is %u.", (unsigned)val);
    state->config_vector = val;
    state->irqs_changed  = true;
    break;
  case VIRTIO_MSI_QUEUE_VECTOR:
    LOG(state, "Queue %u configured to trigger MSI-X vector %u.",
	state->queue_sel, (unsigned)val);
    state->vq[state->queue_sel].vector = val;
    state->irqs_changed  = true;
    break;
  default:
    LOG(state, "Unimplemented register %" PRIx64, addr);
  }
}

/* EOF */
