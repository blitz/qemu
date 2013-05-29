/* Utility macros taken from qemu and gcc docs. */

#pragma once

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

#define MIN(a, b)		\
  ({ __typeof__ (a) _a = (a);	\
    __typeof__ (b) _b = (b);	\
    _a < _b ? _a : _b; })

#define likely(x)   __builtin_expect(!!(x), 1)
#define unlikely(x)   __builtin_expect(!!(x), 0)

/* EOF */
