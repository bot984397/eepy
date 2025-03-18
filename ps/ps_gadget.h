#ifndef __PS_GADGET_H__
#define __PS_GADGET_H__

/* @file    ps_gadget.h
 * @author  vmx
 * @brief   libc gadget enumeration header
 */

struct ps_gadget_ctx {
   uintptr_t pop_rdi;
   uintptr_t pop_rsi;
   uintptr_t pop_rdx;
   uintptr_t pop_rax;
   uintptr_t pop_rdx_rcx_rbx;
};

struct ps_mem_range {
   void *start;            // base addr
   uintptr_t size;         // size in bytes
   int prot;
};

int ps_gadget_init(uintptr_t *libc_base, uintptr_t *libc_size);
int ps_gadget_scan(uintptr_t libc_base, uintptr_t libc_size,
                   struct ps_gadget_ctx *gadget_ctx);

struct ps_mem_range *ps_gadget_get_ranges(int prot_all, void *image_base,
                                          int *num_ranges);
void ps_gadget_build_chain(struct ps_gadget_ctx *ctx, int prot_all,
                           void *image_base, uint32_t duration);

#endif /* __PS_GADGET_H__ */
