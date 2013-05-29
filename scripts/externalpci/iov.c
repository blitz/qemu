/* IO Vector Utilities */

#include <string.h>

#include "iov.h"
#include "util.h"

size_t 
iov_size(const struct iovec *iov, const unsigned int iov_cnt)
{
    size_t len;
    unsigned int i;

    len = 0;
    for (i = 0; i < iov_cnt; i++) {
	len += iov[i].iov_len;
    }
    return len;
}

unsigned
iov_move(struct iovec *dst_iov, unsigned int dst_iov_cnt,
	 const struct iovec *src_iov, unsigned int src_iov_cnt,
	 size_t src_offset)
{
  size_t len        = 0;
  size_t dst_offset = 0;	/* Offset in current segment */
  size_t dst_i      = 0;
  size_t dst_space  = dst_iov[0].iov_len; /* Space left in current
					     destination segment. */

  for (unsigned src_i = 0; src_i < src_iov_cnt; src_i++) {
    /* Skip to first segment after the offset. */
    if (src_offset >= src_iov[src_i].iov_len) {
      src_offset -= src_iov[src_i].iov_len;
      continue;
    }

    // assert(dst_offset + dst_space == dst_iov[dst_i].iov_len);
    do {
      size_t chunk = MIN(dst_space, src_iov[src_i].iov_len - src_offset);

      memcpy(dst_iov[dst_i].iov_base + dst_offset,
	     src_iov[src_i].iov_base + src_offset,
	     chunk);

      len        += chunk;
      dst_offset += chunk;
      dst_space  -= chunk;
      src_offset += chunk;

      if (dst_space == 0) {
	dst_i += 1;
	if (dst_i >= dst_iov_cnt) {
	  return dst_i;
	}

	dst_offset = 0;
	dst_space  = dst_iov[dst_i].iov_len;
      }
    } while (src_offset < src_iov[src_i].iov_len);

    src_offset = 0;
  }

  /* Source is consumed. */
  if (dst_offset != 0) {
    dst_iov[dst_i].iov_len = dst_offset;
    return dst_i + 1;
  } else {
    return dst_i;
  }
}

/* EOF */
