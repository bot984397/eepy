/* @file    eepy.c
 * @author  <vmx@0x6e63.com>
 * @brief   eepy sleep obfuscator
 */

#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <elf.h>
#include <sys/mman.h>
#include <sys/auxv.h>
#include <eepy/eepy.h>
#include <openssl/rc4.h>
#include <openssl/rand.h>

/* <elf.h> doesn't have this for some reason? */
#if __SIZEOF_POINTER__ == 8
#define ElfW(type) Elf64_##type
#else
#define ElfW(type) Elf32_##type
#endif

#define ROP_CALL_2(_rop_ctx, val1, val2, fn_ptr) \
   __push((uintptr)fn_ptr); \
   __push((uintptr)val2); \
   __push((uintptr)_rop_ctx->pop_rsi); \
   __push((uintptr)val1); \
   __push((uintptr)_rop_ctx->pop_rdi)

#define ROP_CALL_3(_rop_ctx, val1, val2, val3, fn_ptr) \
   __push((uintptr)fn_ptr); \
   __push((uintptr)0); \
   __push((uintptr)0); \
   __push((uintptr)val3); \
   __push((uintptr)_rop_ctx->pop_rdx_rcx_rbx); \
   __push((uintptr)val2); \
   __push((uintptr)_rop_ctx->pop_rsi); \
   __push((uintptr)val1); \
   __push((uintptr)_rop_ctx->pop_rdi)

#define ROP_CALL_4(_rop_ctx, val1, val2, val3, val4, fn_ptr) \
   __push((uintptr)fn_ptr); \
   __push((uintptr)0); \
   __push((uintptr)val4); \
   __push((uintptr)val3); \
   __push((uintptr)_rop_ctx->pop_rdx_rcx_rbx); \
   __push((uintptr)val2); \
   __push((uintptr)_rop_ctx->pop_rsi); \
   __push((uintptr)val1); \
   __push((uintptr)_rop_ctx->pop_rdi)

/* @brief   pushes a value onto the stack
 * @param   val: value to push
 * @retval  none
 * @note    this routine needs to be inlined at all times
 */
static inline __attribute__((always_inline)) void __push(uintptr val) {
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

struct mem_range_t {
   void *start;            // base addr
   uintptr size;         // size in bytes
   int prot;
};

static int eepy_get_libc(uintptr *base, uintptr *size) {
   if (!base | !size) {
      return(0);
   }
   FILE *maps = fopen("/proc/self/maps", "r");
   if (!maps) {
      perror("fopen");
      return(0);
   }
   uintptr l_start = 0;
   uintptr l_size = 0;

   char line[256];
   while (fgets(line, sizeof(line), maps)) {
      if (strstr(line, "libc") && strstr(line, "/lib")) {
         uintptr start, end;
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
      return(0);
   }
   *base = l_start;
   *size = l_size;
   return(1);
}

static int eepy_get_gadgets(struct eepy_ctx *ctx, uintptr libc_base, 
                            uintptr libc_size) {
   if (!ctx || !libc_base || !libc_size) {
      return(0);
   }

   void *pop_rdi = NULL;
   void *pop_rsi = NULL;
   void *pop_rdx_rcx_rbx = NULL;
   void *pop_rax = NULL;
   void *syscall = NULL;
   void *jmp_rax = NULL;

   unsigned char *start = (unsigned char*)libc_base;
   for (uintptr i = 0; i < libc_size; i++) {
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
      return(0);
   }
   ctx->pop_rsi = (uintptr)pop_rsi;
   ctx->pop_rdi = (uintptr)pop_rdi;
   ctx->pop_rdx_rcx_rbx = (uintptr)pop_rdx_rcx_rbx;
   return(1);
}

static int eepy_get_base(struct eepy_ctx *ctx) {
   ElfW(Phdr) *phdr = (ElfW(Phdr) *)getauxval(AT_PHDR);
   if (!phdr) {
      return(0);
   }
   ElfW(Ehdr) *ehdr = (ElfW(Ehdr) *)((uintptr)phdr - phdr->p_offset);
   ctx->prog_base = (void*)ehdr;
   return(1);
}

int eepy_init(struct eepy_ctx *ctx) {
   uintptr libc_base, libc_size;
   if (!eepy_get_libc(&libc_base, &libc_size)) {
      return(0);
   }
   if (!eepy_get_gadgets(ctx, libc_base, libc_size)) {
      return(0);
   }
   if (!eepy_get_base(ctx)) {
      return(0);   
   }
   return(1);
}

static struct mem_range_t *eepy_get_ranges(void *img_base, int *num_ranges) {
   ElfW(Ehdr) *ehdr = (ElfW(Ehdr)*)img_base;
   if (ehdr->e_ident[EI_MAG0] != ELFMAG0 ||
       ehdr->e_ident[EI_MAG1] != ELFMAG1 ||
       ehdr->e_ident[EI_MAG2] != ELFMAG2 ||
       ehdr->e_ident[EI_MAG3] != ELFMAG3) {
      printf("ps_gadget_get_ranges: invalid elf header\n");
      return(NULL);
   }

   int num_seg = 0, j = 0;
   struct mem_range_t *ranges;
   ElfW(Phdr) *phdr = (ElfW(Phdr)*)((char*)img_base + ehdr->e_phoff);

   for (int i = 0; i < ehdr->e_phnum; i++) {
      ElfW(Phdr) *seg = &phdr[i];
      if (seg->p_type != PT_LOAD) {
         continue;
      }
      num_seg++;
   }
   ranges = malloc(sizeof(struct mem_range_t) * num_seg);

   for (int i = 0; i < ehdr->e_phnum; i++) {
      ElfW(Phdr) *seg = &phdr[i];
      if (seg->p_type != PT_LOAD) {
         continue;
      }

      int prot = 0;
      if (seg->p_flags & PF_R) prot |= PROT_READ;
      if (seg->p_flags & PF_W) prot |= PROT_WRITE;
      if (seg->p_flags & PF_X) prot |= PROT_EXEC;

      ranges[j].start = img_base + (seg->p_vaddr & ~(getpagesize() - 1));
      ranges[j].size = (seg->p_memsz + getpagesize() - 1) 
                     & ~(getpagesize() - 1);
      ranges[j].prot = prot;
      j++;
   }
   *num_ranges = num_seg;
   return(ranges);
}

static void eepy_get_heap_range(struct mem_range_t *heap_range) {
   if (!heap_range) {
      return;
   }

   FILE *maps = fopen("/proc/self/maps", "r");
   uintptr l_start = 0, l_size = 0;
   char line[256];

   while (fgets(line, sizeof(line), maps)) {
      if (strstr(line, "[heap]")) {
         uintptr start, end;
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

void bedtime(struct eepy_ctx *ctx, u32 sleep) {
   if (!ctx || !sleep) {
      return;
   }

   int num_ranges = 0;
   struct mem_range_t *mem_ranges = eepy_get_ranges(ctx->prog_base,
                                                     &num_ranges);
   struct mem_range_t heap_range = {0};
   eepy_get_heap_range(&heap_range);

   RC4_KEY rc4_key;
   unsigned char key_bytes[16];
   RAND_bytes(key_bytes, 16);

   struct timespec timespec_t;
   timespec_t.tv_sec = sleep;
   timespec_t.tv_nsec = 0;

   void *ret_addr = &&ps_chain_ret;
   __push((uintptr)ret_addr);         // final return address

   /* mprotect regions back to original protection */
   for (int i = 0; i < num_ranges; i++) {
      ROP_CALL_3(ctx, mem_ranges[i].start, mem_ranges[i].size,
                 mem_ranges[i].prot, mprotect);
   }

   /* decrypt heap */
   ROP_CALL_4(ctx, &rc4_key, heap_range.size, heap_range.start,
              heap_range.start, RC4);

   /* set up arc4 key */
   ROP_CALL_3(ctx, &rc4_key, 16, key_bytes, RC4_set_key);

   /* decrypt regions */
   for (int i = 0; i < num_ranges; i++) {
      ROP_CALL_4(ctx, &rc4_key, mem_ranges[i].size, mem_ranges[i].start,
                 mem_ranges[i].start, RC4); 
   }

   /* set up arc4 key */
   ROP_CALL_3(ctx, &rc4_key, 16, key_bytes, RC4_set_key);

   /* nanosleep */
   ROP_CALL_2(ctx, &timespec_t, NULL, nanosleep);

   /* encrypt regions */
   for (int i = 0; i < num_ranges; i++) {
      ROP_CALL_4(ctx, &rc4_key, mem_ranges[i].size, mem_ranges[i].start,
                 mem_ranges[i].start, RC4);
   } 

   /* set up arc4 key */
   ROP_CALL_3(ctx, &rc4_key, 16, key_bytes, RC4_set_key);

   /* encrypt heap */
   ROP_CALL_4(ctx, &rc4_key, heap_range.size, heap_range.start,
              heap_range.start, RC4);

   /* set up arc4 key */
   ROP_CALL_3(ctx, &rc4_key, 16, key_bytes, RC4_set_key);

   /* mprotect regions to rw */
   for (int i = 0; i < num_ranges; i++) {
      ROP_CALL_3(ctx, mem_ranges[i].start, mem_ranges[i].size,
                 (PROT_READ | PROT_WRITE), mprotect);
   }

   free(mem_ranges);
   /* start rop chain - execution continues at [ps_chain_ret] */
   __ret();

ps_chain_ret:
   return;
}
