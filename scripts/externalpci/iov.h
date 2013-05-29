#pragma once

#include <stdlib.h>
#include <sys/uio.h>

/* Return the length of all buffers in this I/O vector. */
size_t iov_size(const struct iovec *iov, const unsigned int iov_cnt);

/* Copy data from one I/O vector to another. Modifies the last
   descriptor in the destination list to have the correct length and
   returns the index of this last descriptor. */
unsigned iov_move(struct iovec *dst_iov, unsigned int dst_iov_cnt,
		  const struct iovec *src_iov, unsigned int src_iov_cnt,
		  size_t src_offset);


/* EOF */
