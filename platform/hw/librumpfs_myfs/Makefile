.include <bsd.own.mk>
.include "../../../filesystem.mk"

LIB=    rumpfs_myfs

SRCS=   myfs.c
SRCS+=  myfs_component.c

RUMPTOP= ${TOPRUMP}

CPPFLAGS+=      -I${RUMPTOP}/librump/rumpkern
CPPFLAGS+=      -I${.CURDIR}
CPPFLAGS+=	-I${.CURDIR}/../include
CPPFLAGS+=	-I${.CURDIR}/../../../include
CPPFLAGS+=	${FSDOM_FLAG}

RUMPCOMP_USER_SRCS=     myfs_user.c
RUMPCOMP_USER_CPPFLAGS+= -I${.CURDIR}/..
RUMPCOMP_USER_CPPFLAGS+= -I${.CURDIR}/../include
RUMPCOMP_USER_CPPFLAGS+= -I${.CURDIR}/../../xen/xen/include
RUMPCOMP_USER_CPPFLAGS+= -I${.CURDIR}/../../../include
RUMPCOMP_USER_CPPFLAGS+= -I../../include
RUMPCOMP_USER_CPPFLAGS+= ${FSDOM_FLAG}

# XXX
.undef RUMPKERN_ONLY

.include "${RUMPTOP}/Makefile.rump"
.include <bsd.lib.mk>
.include <bsd.klinks.mk>
