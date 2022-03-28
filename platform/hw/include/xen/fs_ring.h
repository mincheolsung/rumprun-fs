#ifndef __FS_RING_H__
#define __FS_RING_H__

#include <bmk-core/types.h>
#include <bmk-core/lfring.h>
#include <bmk-pcpu/pcpu.h>

#define FSDOM_RING_ORDER	9
#define FSDOM_RING_SIZE	(1U << FSDOM_RING_ORDER)

#define FSDOM_DATA_SIZE	1024
#define FSDOM_RING_DATA_PAGES	((FSDOM_DATA_SIZE * FSDOM_RING_SIZE +	\
			BMK_PCPU_PAGE_SIZE - 1) / BMK_PCPU_PAGE_SIZE)

struct fsdom_aring {
	_Alignas(LF_CACHE_BYTES) _Atomic(long) readers;
	_Alignas(LFRING_ALIGN) char ring[0];
};

struct fsdom_fring {
	_Alignas(LFRING_ALIGN) char ring[0];
};

#endif
