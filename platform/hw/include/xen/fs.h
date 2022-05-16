#ifndef __FS_H__
#define __FS_H__

#include <bmk-core/types.h>
#include "fs_ring.h"

#define SYSID_FS 2

#define OPEN 1
#define OPENAT 2
#define WRITE 3
#define READ 4
#define CLOSE 5
#define FCNTL 6
#define LSEEK 7
#define FSYNC 8
#define FSTAT 9
#define STAT 10
#define LSTAT 11
#define STATVFS1 12
#define PREAD 13
#define PWRITE 14
#define ACCESS 15
#define MKDIR 16
#define RMDIR 17
#define CHOWN 18
#define DUP2 19
#define CHDIR 20
#define UNLINK 21

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
