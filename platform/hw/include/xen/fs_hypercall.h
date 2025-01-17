#ifndef __HYPERCALL_H__
#define __HYPERCALL_H__

#include <mini-os/hypervisor.h>

#ifndef __HYPERVISOR_syscall_service_op
# define __HYPERVISOR_syscall_service_op	46
#endif

#ifndef __HYPERVISOR_syscall_port_bind
# define __HYPERVISOR_syscall_port_bind		47
#endif

#ifndef DOMID_BACKEND
# define DOMID_BACKEND	xen_mk_uint(0x7FFA)
#endif

static inline int
HYPERVISOR_syscall_service_op(
		int op, int sysid, void *ptr)
{
	return _hypercall3(int, syscall_service_op, op, sysid, ptr);
}

#if 0
static inline int
HYPERVISOR_syscall_port_bind(
		int sysid, uint16_t port, uint8_t protocol)
{
	return _hypercall3(int, syscall_port_bind, sysid, port, protocol);
}
#endif
#endif /* __HYPERCALL__ */
