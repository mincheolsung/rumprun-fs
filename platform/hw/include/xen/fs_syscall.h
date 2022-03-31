typedef long int register_t;
#define SYS_MAXSYSARGS  8
#define syscallarg(x)                                                   \
	union {                                                         \
		register_t pad;                                         \
		struct { x datum; } le;                                 \
		struct { /* LINTED zero array dimension */              \
			int8_t pad[  /* CONSTCOND */                    \
				(sizeof (register_t) < sizeof (x))      \
				? 0                                     \
				: sizeof (register_t) - sizeof (x)];    \
				x datum;                                \
		} be;                                                   \
	}

#define check_syscall_args(call) /*LINTED*/ \
	typedef char call##_check_args[sizeof (struct call##_args) \
	<= SYS_MAXSYSARGS * sizeof (register_t) ? 1 : -1];

#define SCARG(p,k)      ((p)->k.le.datum)
struct sys_read_args {
	syscallarg(int) fd;
	syscallarg(void *) buf;
	syscallarg(size_t) nbyte;
};
check_syscall_args(sys_read)

struct sys_write_args {
	syscallarg(int) fd;
	syscallarg(const void *) buf;
	syscallarg(size_t) nbyte;
};
check_syscall_args(sys_write)

struct sys_open_args {
	syscallarg(const char *) path;
	syscallarg(int) flags;
	syscallarg(mode_t) mode;
};
check_syscall_args(sys_open)

struct sys_close_args {
	syscallarg(int) fd;
};

struct sys_fcntl_args {
	syscallarg(int) fd;
	syscallarg(int) cmd;
	syscallarg(void *) arg;
};

check_syscall_args(sys_close)