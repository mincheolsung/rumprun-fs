#ifndef _BMK_PCPU_PCPU_H_
#define _BMK_PCPU_PCPU_H_

#define BMK_PCPU_PAGE_SHIFT 12UL
#define BMK_PCPU_PAGE_SIZE (1<<BMK_PCPU_PAGE_SHIFT)
#define BMK_PCPU_L1_SHIFT 7
#define BMK_PCPU_L1_SIZE 128

struct bmk_cpu_info {
	__attribute__ ((aligned(BMK_PCPU_L1_SIZE))) struct bmk_cpu_info *self;
	struct bmk_thread *idle_thread;
	unsigned long cpu;
	/* Interrupt enabling/disabling. */
	unsigned long spldepth;
	/* Base time values at the last call to tscclock_monotonic(). */
	unsigned long long time_base;
	unsigned long long tsc_base;
	__attribute__ ((aligned(BMK_PCPU_L1_SIZE))) char _pad[0];
};

#define bmk_get_cpu(x)														\
	__extension__ ({														\
		__typeof__ (((struct bmk_cpu_info *)0)->x) __val;					\
		__asm__ ("mov %%gs:%p1, %0"											\
				: "=r" (__val)												\
				: "i" (__builtin_offsetof(struct bmk_cpu_info, x))			\
		);																	\
		__val; 																\
	})

#define bmk_set_cpu(x, v)													\
	__extension__ ({														\
		__typeof__ (((struct bmk_cpu_info *)0)->x) __val = (v);				\
		if (sizeof(__val) == 8) {											\
			__asm__ ("movq %0, %%gs:%p1"									\
					:														\
					: "ri" (__val),											\
					  "i" (__builtin_offsetof(struct bmk_cpu_info, x))		\
					: "memory"												\
			);																\
		} else {															\
			__asm__ ("movl %0, %%gs:%p1"									\
					:														\
					: "ri" (__val),											\
					  "i" (__builtin_offsetof(struct bmk_cpu_info, x))		\
					: "memory"												\
			);																\
		}																	\
	})

#define bmk_add_cpu(x, v)													\
	__extension__ ({														\
		__typeof__ (((struct bmk_cpu_info *)0)->x) __val = (v);				\
		unsigned char __res;												\
		if (sizeof(__val) == 8) {											\
			__asm__ ("addq %1, %%gs:%p2"									\
					: "=@ccz" (__res)										\
					: "ri" (__val),											\
					  "i" (__builtin_offsetof(struct bmk_cpu_info, x))		\
					: "memory", "cc"										\
			);																\
		} else {															\
			__asm__ ("addl %1, %%gs:%p2"									\
					: "=@ccz" (__res)										\
					: "ri" (__val),											\
					  "i" (__builtin_offsetof(struct bmk_cpu_info, x))		\
					: "memory", "cc"										\
			);																\
		}																	\
		__res;																\
	})

#define bmk_sub_cpu(x, v)													\
	__extension__ ({														\
		__typeof__ (((struct bmk_cpu_info *)0)->x) __val = (v);				\
		unsigned char __res;												\
		if (sizeof(__val) == 8) {											\
			__asm__ ("subq %1, %%gs:%p2"									\
					: "=@ccz" (__res)										\
					: "ri" (__val),											\
					  "i" (__builtin_offsetof(struct bmk_cpu_info, x))		\
					: "memory", "cc"										\
			);																\
		} else {															\
			__asm__ ("subl %1, %%gs:%p2"									\
					: "=@ccz" (__res)										\
					: "ri" (__val),											\
					  "i" (__builtin_offsetof(struct bmk_cpu_info, x))		\
					: "memory", "cc"										\
			);																\
		}																	\
		__res;																\
	})

#define bmk_get_cpu_info()	bmk_get_cpu(self)

static inline void bmk_set_cpu_info(struct bmk_cpu_info *cpu)
{
	unsigned long p = (unsigned long) cpu;

	cpu->self = cpu;
	__asm__ __volatile__ ("wrmsr" ::
		"c" (0xc0000101),
		"a" ((unsigned)(p)),
		"d" ((unsigned)(p >> 32))
	);
}

static inline void bmk_cpu_relax(void)
{
	__asm__ __volatile__ ("pause" ::: "memory");
}

#endif /* _BMK_PCPU_PCPU_H_ */
