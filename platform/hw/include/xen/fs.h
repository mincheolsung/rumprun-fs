#ifndef __FS_H__
#define __FS_H__

#include <bmk-core/types.h>
#include "fs_ring.h"

#define SYSID_FS 2

#define OPEN 1
#define WRITE 2
#define READ 3
#define CLOSE 4
#define FCNTL 5
#define LSEEK 6
#define FSYNC 7
#define FSTAT 8
#define STAT 9
#define LSTAT 10
#define STATVFS1 11
#define PREAD 12
#define PWRITE 13
#define ACCESS 14
#define MKDIR 15
#define CHOWN 16
#define DUP2 17

typedef uint32_t evtchn_port_t;
typedef uint32_t grant_ref_t;

typedef struct frontend_grefs {
	uint64_t base;
	uint64_t len;
	uint64_t fring_addr;
        evtchn_port_t frontend_sender_port;
        evtchn_port_t backend_sender_port;
        grant_ref_t range_grefs[0];
} frontend_grefs_t;

int frontend_send(void *, long int *);
void frontend_init(void);
void backend_init(void);
void backend_connect(evtchn_port_t);
void backend_send(void *);
#endif
