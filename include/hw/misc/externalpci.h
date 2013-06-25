/**
 * Data structures for externally implemented PCI devices
 *
 * Copyright (C) 2013, Julian Stecklina <jsteckli@os.inf.tu-dresden.de>
 * Economic rights: Technische Universitaet Dresden (Germany)
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#pragma once

#include <stdint.h>
#include <stdbool.h>

#include "../pci/pci_regs.h"

/* The request/response notion is from the view of qemu. Thus
   everything qemu sends is a request and it gets responses from the
   backend. */

enum {
  EXTERNALPCI_REQ_REGION,
  EXTERNALPCI_REQ_PCI_INFO,
  EXTERNALPCI_REQ_IOT,
  EXTERNALPCI_REQ_IRQ,
  EXTERNALPCI_REQ_RESET,
  EXTERNALPCI_REQ_EXIT,
};

typedef struct externalpci_region externalpci_region;
typedef struct externalpci_req    externalpci_req;
typedef struct externalpci_res    externalpci_res;

typedef struct externalpci_iot_req externalpci_iot_req;
typedef struct externalpci_iot_res externalpci_iot_res;

typedef struct externalpci_irq_req externalpci_irq_req;
typedef struct externalpci_irq_res externalpci_irq_res;

typedef struct externalpci_pci_info_res externalpci_pci_info_res;

struct externalpci_region {
  /* Memory region is represented by this file descriptor at the given
     offset. */
  int fd;
  uint64_t offset;

  uint64_t phys_addr;
  uint64_t size;
};

struct externalpci_irq_req {
  /* An eventfd. Qemu ties this to KVM. The external process can write
     to this to trigger an IRQ. */

  int fd;
  
  /* Index of IRQ info to be requested. Qemu queries this starting
     from zero. Response indicates whether there are more. */
  int idx;
};

struct externalpci_irq_res {
  bool valid;                   /* Does the external process want to use this FD? */
  bool more;                    /* More IRQs to query? */
};

/* IO transaction. */
struct externalpci_iot_req {
  uint64_t hwaddr;
  uint32_t value;		/* Only for write */
  uint8_t  size;		/* 1-4 */
  uint8_t  bar;
  enum { IOT_READ, IOT_WRITE } type;
};

struct externalpci_iot_res {
  uint32_t value;		/* Only for read */
};

struct externalpci_pci_info_res {
  uint16_t vendor_id;
  uint16_t device_id;

  uint16_t subsystem_id;
  uint16_t subsystem_vendor_id;

  uint8_t  msix_vectors;

  /* We currently support a single hotspot. Access to hotspots trigger
     an eventfd. */
  uint8_t  hotspot_bar;
  uint16_t hotspot_addr;
  uint8_t  hotspot_size;
  int      hotspot_fd;

  struct {
    /* Lowest bits contain type of BAR etc. */
    uint32_t size;
  } bar[6];
};

struct externalpci_req {
  uint32_t type;

  union {
    externalpci_region  region;
    externalpci_iot_req iot_req;
    externalpci_irq_req irq_req;
  };
};

enum {
  /* IRQ config has been changed. Qemu needs to pull new IRQ
     config. */
  EXTERNALPCI_RES_FLAG_FETCH_IRQS = (1 << 0),
};

struct externalpci_res {
  uint32_t type;
  uint32_t flags;

  
  union {
    externalpci_pci_info_res pci_info;
    externalpci_iot_res      iot_res;
    externalpci_irq_res      irq_res;
  };
};

/* EOF */
