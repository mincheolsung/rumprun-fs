#ifndef __FS_RING_H__
#define __FS_RING_H__

#include <bmk-core/types.h>
#include <bmk-core/lfring.h>
#include <bmk-pcpu/pcpu.h>

#define FSDOM_RING_ORDER	9
#define FSDOM_RING_SIZE	(1U << FSDOM_RING_ORDER)

#define FSDOM_DATA_SIZE	32
#define FSDOM_RING_DATA_PAGES	((FSDOM_DATA_SIZE * FSDOM_RING_SIZE +	\
			BMK_PCPU_PAGE_SIZE - 1) / BMK_PCPU_PAGE_SIZE)

#define RING_PAGES ((LFRING_SIZE(FSDOM_RING_ORDER) + BMK_PCPU_PAGE_SIZE - 1) / BMK_PCPU_PAGE_SIZE)

/* ring buffer structures */
#define FSDOM_FRING(fring) \
        ((struct fsdom_fring *) ((char *) fring + 0 * RING_PAGES * PAGE_SIZE))

#define FSDOM_REQ_ARING(fring) \
        ((struct fsdom_aring *) ((char *) fring + 1 * RING_PAGES * PAGE_SIZE))

#define FSDOM_RSP_ARING(fring) \
        ((struct fsdom_aring *) ((char *) fring + 2 * RING_PAGES * PAGE_SIZE))

#define FSDOM_BUF(fring) \
        ((char *) fring + 3 * RING_PAGES * PAGE_SIZE)

struct fsdom_aring {
	_Alignas(LF_CACHE_BYTES) _Atomic(long) readers;
	_Alignas(LFRING_ALIGN) char ring[0];
};

struct fsdom_fring {
	_Alignas(LF_CACHE_BYTES) _Atomic(long) readers;
	_Alignas(LFRING_ALIGN) char ring[0];
};

#endif
