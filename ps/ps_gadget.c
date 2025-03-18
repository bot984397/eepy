/* @file    ps_gadget.c
 * @author  vmx
 * @brief   libc gadget enumeration implementation
 */

#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <elf.h>
#include <time.h>
#include <sys/mman.h>
#include <ps/ps_gadget.h>

#if __SIZEOF_POINTER__ == 8
#define ElfW(type) Elf64_##type
#else
#define ElfW(type) Elf32_##type
#endif

/* @brief   pushes a value onto the stack
 * @param   val: value to push
 * @retval  none
 * @note    this routine needs to be inlined at all times
 */
static inline __attribute__((always_inline)) void __push(uintptr_t val) {
   __asm__ volatile(
      "push %0\n"
      :
      : "r" (val)
      : "memory"
   );
}

/* @brief   inline return function to start rop chain
 * @retval  none
 */
static inline __attribute__((always_inline)) void __ret(void) {
   __asm__ volatile(
      "ret\n"
   );
}

/* @brief   gets libc executable section base addr + size
 * @param   libc_base: libc base address on success, otherwise undefined
 * @param   libc_size: libc size on success, otherwise undefined
 * @retval  1 on success, 0 otherwise
 */
int ps_gadget_init(uintptr_t *libc_base, uintptr_t *libc_size) {
   if (!libc_base || !libc_size) {
      return 0;
   }

   FILE *maps = fopen("/proc/self/maps", "r");
   if (!maps) {
      perror("fopen");
      return 0;
   }

   uintptr_t l_start = 0;
   uintptr_t l_size = 0;

   char line[256];
   while (fgets(line, sizeof(line), maps)) {
      if (strstr(line, "libc") && strstr(line, "/lib")) {
         uintptr_t start, end;
         char perms[5];
         if (sscanf(line, "%lx-%lx %4s", &start, &end, perms) == 3) {
            if (strcmp(perms, "r-xp") == 0) {
               l_size = end - start;
               l_start = start;
               break;
            }
         }
      }
   }

   fclose(maps);
   if (!l_start || !l_size) {
      return 0;
   }
   *libc_base = l_start;
   *libc_size = l_size;
   return 1;
}

/* @brief   scans libc for rop gadgets
 * @param   libc_base: libc executable region base address
 * @param   libc_size: libc executable region size
 * @param   gadget_ctx: rop gadget context populated on success
 * @retval  1 on success, 0 otherwise
 */
int ps_gadget_scan(uintptr_t libc_base, uintptr_t libc_size,
                   struct ps_gadget_ctx *gadget_ctx) {
   printf("scanning for gadgets [libc base: %lx]\n", libc_base);
   if (!libc_base || !libc_size || !gadget_ctx) {
      return 0;
   }

   /* rop chain structure
    * [1] mprotect executable region to rw
    * [2] encrypt regions (only exec / all depending on cfg)
    * [3] sleep for specified duration
    * [4] decrypt regions (only exec / all depending on cfg)
    * [5] mprotect executable region to rx
    */

   void *pop_rdi = NULL;
   void *pop_rsi = NULL;
   void *pop_rdx_rcx_rbx = NULL;
   void *pop_rax = NULL;
   void *syscall = NULL;
   void *jmp_rax = NULL;

   unsigned char *start = (unsigned char*)libc_base;
   for (size_t i = 0; i < libc_size; i++) {
      if (start[i] == 0xC3) {
         /* pop rdx; pop rcx; pop rbx; ret */
         if (i >= 3 && pop_rdx_rcx_rbx == NULL &&
             start[i - 1] == 0x5B &&
             start[i - 2] == 0x59 &&
             start[i - 3] == 0x5A) {
            pop_rdx_rcx_rbx = &start[i - 3];
         }
         /* pop rdi; ret */
         if (i >= 1 && pop_rdi == NULL &&
             start[i - 1] == 0x5F) {
            pop_rdi = &start[i - 1];
         }
         /* pop rsi; ret */
         if (i >= 1 && pop_rsi == NULL &&
             start[i - 1] == 0x5E) {
            pop_rsi = &start[i - 1];
         }
         /* pop rax; ret */
         if (i >= 1 && pop_rax == NULL &&
             start[i - 1] == 0x58) {
            pop_rax = &start[i - 1];
         }
      }
      /* jmp rax */
      if (i >= 1 && jmp_rax == NULL &&
          start[i - 0] == 0xE0 &&
          start[i - 1] == 0xFF) {
         jmp_rax = &start[i - 1];
      }
      /* syscall */
      if (i >= 1 && syscall == NULL &&
          start[i - 0] == 0x05 &&
          start[i - 1] == 0x0F) {
         syscall = &start[i - 1];
      }
   }

   if (!pop_rdi || !pop_rsi || !pop_rdx_rcx_rbx || !pop_rax || !syscall ||
       !jmp_rax) {
      printf("one or more gadgets are missing\n");
      return 0;
   }

   gadget_ctx->pop_rsi = (uintptr_t)pop_rsi;
   gadget_ctx->pop_rdi = (uintptr_t)pop_rdi;
   gadget_ctx->pop_rdx_rcx_rbx = (uintptr_t)pop_rdx_rcx_rbx;

   return 1;
}

struct ps_mem_range *ps_gadget_get_ranges(int prot_all, void *image_base,
                                          int *num_ranges) {
   ElfW(Ehdr) *ehdr = (ElfW(Ehdr)*)image_base;
   if (ehdr->e_ident[EI_MAG0] != ELFMAG0 ||
       ehdr->e_ident[EI_MAG1] != ELFMAG1 ||
       ehdr->e_ident[EI_MAG2] != ELFMAG2 ||
       ehdr->e_ident[EI_MAG3] != ELFMAG3) {
      printf("ps_gadget_get_ranges: invalid elf header\n");
      return NULL;
   }

   int num_seg = 0, j = 0;
   struct ps_mem_range *ranges;
   ElfW(Phdr) *phdr = (ElfW(Phdr)*)((char*)image_base + ehdr->e_phoff);

   for (int i = 0; i < ehdr->e_phnum; i++) {
      ElfW(Phdr) *seg = &phdr[i];
      if (seg->p_type != PT_LOAD) {
         continue;
      }
      num_seg++;
   }
   ranges = malloc(sizeof(struct ps_mem_range) * num_seg);

   for (int i = 0; i < ehdr->e_phnum; i++) {
      ElfW(Phdr) *seg = &phdr[i];
      if (seg->p_type != PT_LOAD) {
         continue;
      }

      int prot = 0;
      if (seg->p_flags & PF_R) prot |= PROT_READ;
      if (seg->p_flags & PF_W) prot |= PROT_WRITE;
      if (seg->p_flags & PF_X) prot |= PROT_EXEC;

      ranges[j].start = image_base + (seg->p_vaddr & ~(getpagesize() - 1));
      ranges[j].size = (seg->p_memsz + getpagesize() - 1) 
                     & ~(getpagesize() - 1);
      ranges[j].prot = prot;
      j++;
   }
   *num_ranges = num_seg;
   return ranges;
}

static void ps_get_heap_range(struct ps_mem_range *heap_range) {
   if (!heap_range) {
      return;
   }

   FILE *maps = fopen("/proc/self/maps", "r");
   uintptr_t l_start = 0, l_size = 0;
   char line[256];

   while (fgets(line, sizeof(line), maps)) {
      if (strstr(line, "[heap]")) {
         uintptr_t start, end;
         if (sscanf(line, "%lx-%lx", &start, &end) == 2) {
            l_start = start;
            l_size = end - start;
         }
      }
   }

   if (!l_start || !l_size) {
      return;
   }
   heap_range->start = (void*)l_start;
   heap_range->size = l_size;
}

void ps_gadget_build_chain(struct ps_gadget_ctx *ctx, int prot_all,
                           void *image_base, uint32_t duration) {
   if (!ctx) {
      printf("ps_gadget_build_chain: ctx is NULL\n");
   }

   int num_ranges = 0;
   struct ps_mem_range *mem_ranges = ps_gadget_get_ranges(prot_all, 
                                                          image_base,
                                                          &num_ranges);
   struct ps_mem_range heap_range = {0};
   ps_get_heap_range(&heap_range);

   unsigned char xor_func[] = {
      0x48, 0x85, 0xf6, 0x74, 0x11, 0x48, 0x89, 0xf8,
      0x48, 0x89, 0xf1, 0x41, 0x88, 0xd0, 0x44, 0x30, 0x00, 0x48, 0xff, 0xc0,
      0xe2, 0xf8, 0xc3
   };

   size_t func_size = sizeof(xor_func);
   size_t timespec_offset = (func_size + 0xF) & ~0xF; 
   size_t mmap_size = timespec_offset + sizeof(struct timespec);

   void *mmap_segment = mmap(NULL, mmap_size,
                             PROT_READ | PROT_WRITE | PROT_EXEC,
                             MAP_ANON | MAP_PRIVATE, -1, 0);
   memcpy(mmap_segment, xor_func, func_size);

   struct timespec *timespec_addr = 
      (struct timespec *)((char *)mmap_segment + timespec_offset);
   timespec_addr->tv_sec = duration;
   timespec_addr->tv_nsec = 0;

   void (*xor_enc_fn)(uint8_t*, size_t, uint8_t) = 
      (void (*)(uint8_t*, size_t, uint8_t))mmap_segment;

   /* randomized xor key */
   srand(time(NULL));
   int xor_key = rand() % 256;

   void *ret_addr = &&ps_chain_ret;
   __push((uintptr_t)ret_addr);         // final return address

   // ^
   // ^

   /* mprotect regions back to original protection */
   for (int i = 0; i < num_ranges; i++) {
      __push((uintptr_t)mprotect);
      __push((uintptr_t)0);
      __push((uintptr_t)0);
      __push((uintptr_t)mem_ranges[i].prot);
      __push((uintptr_t)ctx->pop_rdx_rcx_rbx);
      __push((uintptr_t)mem_ranges[i].size);
      __push((uintptr_t)ctx->pop_rsi);
      __push((uintptr_t)mem_ranges[i].start);
      __push((uintptr_t)ctx->pop_rdi);
   }

   // ^
   // ^

   /* decrypt heap */
   __push((uintptr_t)xor_enc_fn);
   __push((uintptr_t)0);
   __push((uintptr_t)0);
   __push((uintptr_t)xor_key);
   __push((uintptr_t)ctx->pop_rdx_rcx_rbx);
   __push((uintptr_t)heap_range.size);
   __push((uintptr_t)ctx->pop_rsi);
   __push((uintptr_t)heap_range.start);
   __push((uintptr_t)ctx->pop_rdi);

   // ^
   // ^

   /* decrypt regions */
   for (int i = 0; i < num_ranges; i++) {
      __push((uintptr_t)xor_enc_fn);
      __push((uintptr_t)0);
      __push((uintptr_t)0);
      __push((uintptr_t)xor_key);
      __push((uintptr_t)ctx->pop_rdx_rcx_rbx);
      __push((uintptr_t)mem_ranges[i].size);
      __push((uintptr_t)ctx->pop_rsi);
      __push((uintptr_t)mem_ranges[i].start);
      __push((uintptr_t)ctx->pop_rdi);
   }

   // ^
   // ^

   /* nanosleep */
   __push((uintptr_t)nanosleep);            // nanosleep addr
   __push((uintptr_t)NULL);                 // rem = NULL
   __push((uintptr_t)ctx->pop_rsi);
   __push((uintptr_t)timespec_addr);        // timespec heap addr
   __push((uintptr_t)ctx->pop_rdi);

   // ^
   // ^

   /* encrypt regions */
   for (int i = 0; i < num_ranges; i++) {
      __push((uintptr_t)xor_enc_fn);
      __push((uintptr_t)0);
      __push((uintptr_t)0);
      __push((uintptr_t)xor_key);
      __push((uintptr_t)ctx->pop_rdx_rcx_rbx);
      __push((uintptr_t)mem_ranges[i].size);
      __push((uintptr_t)ctx->pop_rsi);
      __push((uintptr_t)mem_ranges[i].start);
      __push((uintptr_t)ctx->pop_rdi);
   }

   // ^
   // ^

   /* encrypt heap */
   __push((uintptr_t)xor_enc_fn);
   __push((uintptr_t)0);
   __push((uintptr_t)0);
   __push((uintptr_t)xor_key);
   __push((uintptr_t)ctx->pop_rdx_rcx_rbx);
   __push((uintptr_t)heap_range.size);
   __push((uintptr_t)ctx->pop_rsi);
   __push((uintptr_t)heap_range.start);
   __push((uintptr_t)ctx->pop_rdi);

   // ^
   // ^

   /* mprotect regions to rw if necessary */
   for (int i = 0; i < num_ranges; i++) {
      __push((uintptr_t)mprotect);
      __push((uintptr_t)0);
      __push((uintptr_t)0);
      __push((uintptr_t)(PROT_READ | PROT_WRITE));
      __push((uintptr_t)ctx->pop_rdx_rcx_rbx);
      __push((uintptr_t)mem_ranges[i].size);
      __push((uintptr_t)ctx->pop_rsi);
      __push((uintptr_t)mem_ranges[i].start);
      __push((uintptr_t)ctx->pop_rdi);
   }

   // ^
   // ^

   /* start rop chain - execution continues at [ps_chain_ret] */
   __ret();

ps_chain_ret:
   munmap(mmap_segment, sizeof(xor_func));
   return;
}
