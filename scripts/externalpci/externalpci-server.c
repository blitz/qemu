#define _GNU_SOURCE

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/un.h>
#include <sys/mman.h>
#include <sys/eventfd.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdbool.h>
#include <iso646.h>
#include <inttypes.h>

#include <pthread.h>

#include "hw/misc/externalpci.h"
#include "common.h"

/* The eventfd that is used  */
static int poll_event_fd;

static struct device_state  *state_list;
static struct device_state **state_list_tail = &state_list;

int receive_msg(int session, externalpci_req *req) 
{
  struct msghdr   hdr;
  struct iovec    iov = { req, sizeof(*req) };
  char            chdr_data[CMSG_SPACE(sizeof(int))];
  struct cmsghdr *chdr = (struct cmsghdr *)chdr_data;

  hdr.msg_name       = NULL;
  hdr.msg_namelen    = 0;
  hdr.msg_iov        = &iov;
  hdr.msg_iovlen     = 1;
  hdr.msg_flags      = 0;
  hdr.msg_control    = chdr;
  hdr.msg_controllen = CMSG_SPACE(sizeof(int));

  int res = recvmsg(session, &hdr, 0);
  if (res < 0) {
    perror("recvmsg");
    return -1;
  }

  // Is our connection closed?
  if (res == 0) {
    printf("Disconnected.\n");
    return -1;
  }
    
  if (res != sizeof(*req)) {
    printf("Client violated protocol.\n");
    return -1;
  }

  struct cmsghdr *incoming_chdr = CMSG_FIRSTHDR(&hdr);
  if (incoming_chdr) {
    int fd;
    memcpy(&fd, CMSG_DATA(chdr), sizeof(int));

    if (req->type == EXTERNALPCI_REQ_REGION) {
      req->region.fd = fd;
    } else if (req->type == EXTERNALPCI_REQ_IRQ) {
      req->irq_req.fd = fd;
    } else {
      // printf("... but we didn't expect one!\n");
      close(fd);
      return -1;
    }
  }

  return 0;
}

int send_msg(int session, externalpci_res *res)
{
  struct msghdr   hdr;
  struct iovec    iov = { res, sizeof(*res) };
  char            chdr_data[CMSG_SPACE(sizeof(int))];
  struct cmsghdr *chdr = (struct cmsghdr *)chdr_data;

  hdr.msg_name       = NULL;
  hdr.msg_namelen    = 0;
  hdr.msg_iov        = &iov;
  hdr.msg_iovlen     = 1;
  hdr.msg_flags      = 0;
  hdr.msg_control    = NULL;
  hdr.msg_controllen = 0;

  if (res->type == EXTERNALPCI_REQ_PCI_INFO) {
    // Pass file descriptor
    hdr.msg_control    = chdr;
    hdr.msg_controllen = CMSG_LEN(sizeof(int));
    chdr->cmsg_len    = CMSG_LEN(sizeof(int));
    chdr->cmsg_level  = SOL_SOCKET;
    chdr->cmsg_type   = SCM_RIGHTS;

    memcpy(CMSG_DATA(chdr), &res->pci_info.hotspot_fd, sizeof(int));
  }

  ssize_t err = sendmsg(session, &hdr, MSG_EOR | MSG_NOSIGNAL);
  return (err == (ssize_t)iov.iov_len) ? 0 : -1;
}

static void *
commthread_fn(void *opaque)
{
  struct device_state *state = opaque;
  int session = state->socket;

  while (1) {
    externalpci_req req;
    memset(&req, 0xFF, sizeof(req));
    int err = receive_msg(session, &req);
    if (err) goto fail;
    // printf("Received msg %u.\n", req.type);

    externalpci_res res;
    memset(&res, 0, sizeof(res));
    res.type = req.type;

    switch (req.type) {
    case EXTERNALPCI_REQ_IOT:
      if (req.iot_req.type == IOT_READ)
        res.iot_res.value = vnet_io_read(state, req.iot_req.bar, req.iot_req.hwaddr, req.iot_req.size);
      else {
        vnet_io_write(state, req.iot_req.bar, req.iot_req.hwaddr, req.iot_req.size, req.iot_req.value);
      }
                                         
      LOG(state, "IO: BAR%u %08" PRIx64 " %5s %08" PRIx64 " (%" PRIu32 ")", req.iot_req.bar,
	  req.iot_req.hwaddr, 
	  req.iot_req.type == IOT_READ ? "READ" : "WRITE",
	  (uint64_t)(req.iot_req.type == IOT_READ ? res.iot_res.value : req.iot_req.value),
	  req.iot_req.size);

      /* Notify qemu if it can fetch IRQ info. */
      res.flags           |= (state->irqs_changed ? EXTERNALPCI_RES_FLAG_FETCH_IRQS : 0);
      state->irqs_changed  = false;

      break;
    case EXTERNALPCI_REQ_REGION:
      if (state->cur_region >= MAX_REGIONS) { LOG(state, "Too many regions!"); goto fail; }

      {
	struct region *r = &state->regions[state->cur_region++];
	r->addr_start = req.region.phys_addr;
	r->addr_end   = req.region.phys_addr + req.region.size;
	r->memory     = mmap(NULL, req.region.size, PROT_READ | PROT_WRITE, MAP_SHARED,
			    req.region.fd, req.region.offset);
	if (r->memory == MAP_FAILED) {
	  perror("mmap");
	  close(req.region.fd);
	  goto fail;
	}
	LOG(state, "Mapped %016" PRIx64 "+%08" PRIx64 " to %p.",
	    req.region.phys_addr, req.region.size, r->memory);
	close(req.region.fd);
      }

      break;
    case EXTERNALPCI_REQ_IRQ:
      vnet_irq_info(state, req.irq_req.fd, req.irq_req.idx, &res.irq_res);
      break;
    case EXTERNALPCI_REQ_PCI_INFO:
      vnet_init(state, &res.pci_info);
      res.pci_info.hotspot_fd = poll_event_fd;
      break;
    case EXTERNALPCI_REQ_RESET:
      vnet_reset(state);
      break;
    case EXTERNALPCI_REQ_EXIT:
      LOG(state, "Closing session gracefully.");
      for (unsigned i = 0; i < state->cur_region; i++)
	munmap(state->regions[i].memory, state->regions[i].addr_end - state->regions[i].addr_start);
      goto fail;
    default:
      LOG(state, "Unknown type %u.", req.type);
      goto fail;
    };

    if (send_msg(session, &res) != 0) goto fail;
  }

 fail:
  LOG(state, "Closing session.");
  close(session);
  free(state);
  return NULL;
}

static void *
workerthread_fn(void *arg)
{
  (void)arg;
  
  printf("Worker thread up.\n");

  uint64_t events;
  do {
    bool work_done;

      do {
	work_done = false;

	for (struct device_state *state = state_list;
	     state != NULL; state = state->next) {
	  unsigned count = 32;

	  while (count-- > 0 and vnet_poll(state))
	    work_done = true;
	}
      } while (work_done);


  } while (read(poll_event_fd, &events, sizeof(events)) == sizeof(events));

  printf("Worker thread down.\n");
  return NULL;
}

void
schedule_poll(struct device_state *state)
{
  (void)state;			/* Ignore state for now. */
  
  uint64_t arg = 1;
  write(poll_event_fd, &arg, sizeof(arg));
}

void *translate_pointer(struct device_state *state, hwaddr addr, size_t size)
{
  /* Check for overflow */
  if (addr + size < addr) return NULL;

  for (unsigned i = 0; i < state->cur_region; i++) {
    struct region *r = &state->regions[i];

    if (r->addr_start <= addr and
	addr + size   < r->addr_end)
      return r->memory + (addr - r->addr_start);
  }

  return NULL;
}

void packet_out(struct device_state *state,
		struct iovec *iov, 
		unsigned len, size_t offset)
{
  for (struct device_state *out_s = state_list;
       out_s != NULL; out_s = out_s->next) {
    if (out_s == state) continue;

    /* Broadcast packet */
    if (state->packet_in)
      state->packet_in(out_s, iov, len, offset);
  }
}

int main()
{
  /* Create worker thread */
  poll_event_fd = eventfd(0, 0);
  pthread_t worker;
  pthread_create(&worker, NULL, workerthread_fn, NULL);

  /* Create server */
  int server_sock = socket(AF_LOCAL, SOCK_SEQPACKET, 0);
  if (server_sock < 0) {
    perror("socket");
    return -1;
  }

  struct sockaddr_un addr, client_addr;
  memset(&addr,        0, sizeof(addr));
  memset(&client_addr, 0, sizeof(client_addr));

  addr.sun_family = AF_LOCAL;
  snprintf(addr.sun_path, sizeof(addr.sun_path),
	   "/tmp/externalpci" /* "-%u", getpid() */);

  struct stat st;
  if (stat(addr.sun_path, &st) == 0) {
    if (S_ISSOCK(st.st_mode)) {
      if (unlink(addr.sun_path) != 0)
	perror("unlink");
      printf("Removed stale socket.\n");
    }
  }

  if (0 != bind(server_sock, (struct sockaddr *)(&addr), sizeof(addr))) {
    perror("bind");
    return -1;
  }

  if (0 != listen(server_sock, 1)) {
    perror("listen");
    return -1;
  }

  printf("Ready.\n");

  while (true) {
    socklen_t si = sizeof(client_addr);
    struct device_state *state = calloc(1, sizeof(*state));
    state->socket = accept(server_sock, (struct sockaddr *)(&client_addr), &si);
    if (state->socket < 0) { perror("accept");  break; }
    LOG(state, "Accepted session.");

    /* XXX Locking! */
    *state_list_tail = state;
    state_list_tail  = &state->next;

    pthread_create(&state->commthread, NULL, commthread_fn, state);

  }

  return 0;
}
