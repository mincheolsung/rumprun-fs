#ifndef _RUMPRUN_X86_VAR_H
#define _RUMPRUN_X86_VAR_H 1

#ifndef _LOCORE
struct multiboot_info;
void	x86_boot(struct multiboot_info *, unsigned long);

void	x86_initpic(void);
void	x86_initidt(void);
void	x86_initclocks(void);
void	x86_initclocks_notmain(void);
void	x86_fillgate(int, void *, int);

/* trap "handlers" */
void x86_trap_0(void);
void x86_trap_2(void);
void x86_trap_3(void);
void x86_trap_4(void);
void x86_trap_5(void);
void x86_trap_6(void);
void x86_trap_7(void);
void x86_trap_8(void);
void x86_trap_10(void);
void x86_trap_11(void);
void x86_trap_12(void);
void x86_trap_13(void);
void x86_trap_14(void);
void x86_trap_17(void);
void x86_trap_128(void);

static inline void
x86_cpuid(uint32_t level, uint32_t *eax_out, uint32_t *ebx_out,
		uint32_t *ecx_out, uint32_t *edx_out)
{
	uint32_t eax_, ebx_, ecx_, edx_;

	__asm__ __volatile__ (
		"cpuid"
		: "=a" (eax_), "=b" (ebx_), "=c" (ecx_), "=d" (edx_)
		: "0" (level), "2" (0)
	);
	*eax_out = eax_;
	*ebx_out = ebx_;
	*ecx_out = ecx_;
	*edx_out = edx_;
}

static inline void
x86_rdmsr(uint32_t msr, uint32_t *eax_out, uint32_t *edx_out)
{
	uint32_t eax_, edx_;

	__asm__ __volatile__ (
		"rdmsr"
		: "=a" (eax_), "=d" (edx_)
		: "c" (msr)
	);

	*eax_out = eax_;
	*edx_out = edx_;
}

static inline void
x86_wrmsr(uint32_t msr, uint32_t eax, uint32_t edx)
{
	__asm__ __volatile__ (
		"wrmsr"
		:
		: "a" (eax), "d" (edx), "c" (msr)
	);
}

extern uint8_t pic1mask, pic2mask;
#endif

#endif /* !_RUMPRUN_X86_VAR_H */
