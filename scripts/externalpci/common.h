#pragma once

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>
#include <sys/uio.h>

#include "hw/misc/externalpci.h"

#define MAX_REGIONS 16
#define MAX_MSIX_VECTORS 3

typedef uint64_t hwaddr;

struct region {
  hwaddr addr_start;
  hwaddr addr_end;		/* exclusive */

  char *memory;
};

struct irq {
  int fd;
};

typedef struct VirtQueue VirtQueue;

struct device_state {
  struct device_state *next;

  int       socket;
  pthread_t commthread;

  void (*packet_in)(struct device_state *state, struct iovec *iov,
		    unsigned len, size_t hdr_offset);

  struct region regions[MAX_REGIONS];
  unsigned      cur_region;

  struct irq    irqs[MAX_MSIX_VECTORS];
  bool          irqs_changed;

  /* virtio */
  uint8_t status;
  uint8_t isr;
  uint16_t queue_sel;

  uint32_t guest_features;
  uint32_t host_features;
  bool     mergeable_rx_bufs;

  uint16_t config_vector;
  int nvectors;
  VirtQueue *vq;
};

#define LOG(state, str, ...) fprintf(stderr, "[%03u] " str "\n", (state)->socket,  ## __VA_ARGS__)

void vnet_init    (struct device_state *state, externalpci_pci_info_res *res);
void vnet_irq_info(struct device_state *state, int fd, int msix_idx, externalpci_irq_res *res);

void vnet_reset(struct device_state *state);

uint64_t vnet_io_read(struct device_state *state, unsigned bar, uint64_t addr, unsigned size);
void vnet_io_write(struct device_state *state, unsigned bar, uint64_t addr, unsigned size, uint64_t value);

bool vnet_poll(struct device_state *state);

void schedule_poll(struct device_state *state);
void *translate_pointer(struct device_state *state, hwaddr addr, size_t size);
void packet_out(struct device_state *state, struct iovec *iov, unsigned len, size_t offset);

/* EOF */
