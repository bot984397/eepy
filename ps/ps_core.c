/* @file    ps_core.c
 * @author  vmx
 * @brief   main polysleep implementation
 */

#include <stdio.h>
#include <elf.h>
#include <sys/auxv.h>
#include <ps/ps_core.h>
#include <ps/ps_gadget.h>

/* <elf.h> doesn't have this for some reason? */
#if __SIZEOF_POINTER__ == 8
#define ElfW(type) Elf64_##type
#else
#define ElfW(type) Elf32_##type
#endif

static inline __attribute__((always_inline)) void stack_push(uintptr_t val) {
   __asm__ volatile(
      "push %0\n"
      :
      : "r" (val)
      : "memory"
   );
}

/* @brief   locates gadgets and sets up ROP chain
 * @retval  none
 */
void ps_setup(void) {
   uintptr_t libc_base;
   uintptr_t libc_size;

   struct ps_gadget_ctx ctx;

   if (!ps_gadget_init(&libc_base, &libc_size)) {
      printf("ps_gadget_init failed\n");
      return;
   }

   if (!ps_gadget_scan(libc_base, libc_size, &ctx)) {
      printf("ps_gadget_scan failed\n");
      return;
   }
}

/* @brief   enters the sleep cycle, encrypting the payload in memory
 * @param   delay: sleep duration in ms
 * @retval  none
 */
void ps_sleep(uint32_t delay) {
   if (delay == 0) {
      return;
   }


}

void *ps_get_base_addr(void) {
   ElfW(Phdr) *phdr = (ElfW(Phdr) *)getauxval(AT_PHDR);
   if (!phdr) {
      perror("getauxval(AT_PHDR) failed");
      return NULL;
   }

   ElfW(Ehdr) *ehdr = (ElfW(Ehdr) *)((uintptr_t)phdr - phdr->p_offset);
   return (void *)ehdr;
}
