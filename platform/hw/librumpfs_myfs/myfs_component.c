#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD: component.c,v 1.4 2013/07/04 11:46:51 pooka Exp $");

#include <sys/param.h>
#include <sys/domain.h>
#include <sys/protosw.h>
#include <sys/systm.h>

#include "rump_private.h"
#include "myfs_user.h"

RUMP_COMPONENT(RUMP_COMPONENT_KERN_VFS)
{
	rumpuser_fsdom_init();
}
