#ifndef __FS_H__
#define __FS_H__

#include <bmk-core/types.h>

#define SYSCALL_SERVICE_PREPARE		0
#define SYSCALL_SERVICE_CANCEL		1
#define SYSCALL_SERVICE_CONNECT		2
#define SYSCALL_SERVICE_DISCONNECT	3
#define SYSCALL_SERVICE_CLEANUP		4
#define SYSCALL_SERVICE_REGISTER	5
#define SYSCALL_SERVICE_UNREGISTER	6
#define SYSCALL_SERVICE_REGISTER_APP	7
#define SYSCALL_SERVICE_QUERY		8
#define SYSCALL_SERVICE_FETCH		9
#define SYSCALL_SERVICE_RECONNECT	10
#define SYSCALL_SERVICE_PORT_BIND	11

#define FRONTEND_DEAD	0
#define FRONTEND_ACTIVE 1

#define SYSID_FS 1

#define OPEN 1
#define WRITE 2
#define READ 3
#define CLOSE 4
#define FCNTL 5

typedef uint32_t evtchn_port_t;
typedef uint32_t grant_ref_t;

typedef struct syscall_args {
	uint64_t arg[6];
	struct bmk_thread *thread;
	uint64_t call_id;
} syscall_args_t;

typedef struct frontend_grefs_1 {
	uint32_t len; /* lengh of level1 grefs */
	grant_ref_t range_grefs_1[0];
} frontend_grefs_1_t;

typedef struct frontend_grefs_2 {
	uint64_t base;
	uint64_t fring_addr;
	uint64_t runq_addr;
	uint32_t len; /* lengh of level2 grefs */
	grant_ref_t range_grefs_2[0];
} frontend_grefs_2_t;

typedef struct frontend_connect {
	uint32_t domid;
	uint32_t port;
	uint32_t hello_port;
	uint32_t status;
	grant_ref_t grefs[2];
} frontend_connect_t;

int frontend_syscall(syscall_args_t *args, long int *retval);
void frontend_init(void);

/* backend driver */
#define NUM_OF_DOMS 5

typedef struct backend_connect {
	uint32_t domid;
	uint32_t welcome_port;
	uint32_t *port;
	grant_ref_t tx_gref;
	grant_ref_t rx_gref;
} backend_connect_t;

void backend_init(void);
void backend_connect(evtchn_port_t port);

#endif
