#ifndef __EEPY_H__
#define __EEPY_H__

/* @file    eepy.h
 * @author  <vmx@0x6e63.com>
 * @brief   eepy sleep obfuscator
 */

typedef unsigned int u32;
typedef unsigned long uintptr;

struct eepy_ctx {
   void *prog_base;
   uintptr pop_rdi;
   uintptr pop_rsi;
   uintptr pop_rdx;
   uintptr pop_rax;
   uintptr pop_rdx_rcx_rbx;
};

int eepy_init(struct eepy_ctx *ctx);
void bedtime(struct eepy_ctx *ctx, u32 sleep);

#endif /* __EEPY_H__ */
