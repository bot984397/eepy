#include <stdio.h>
#include <unistd.h>
#include <ps/ps_core.h>
#include <ps/ps_gadget.h>

static void subroutine(void) {
   printf("subroutine called\n");
}

int main(void) {
   printf("pid: %d\n", getpid());

   struct ps_gadget_ctx ctx = {0};
   uintptr_t libc_base, libc_size;
   ps_gadget_init(&libc_base, &libc_size);
   ps_gadget_scan(libc_base, libc_size, &ctx);

   while (1) {
      subroutine();                                            // do work
      ps_gadget_build_chain(&ctx, 0, ps_get_base_addr(), 2);   // sleep
   }
}
