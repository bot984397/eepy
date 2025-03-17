#include <stdio.h>
#include <unistd.h>
#include <ps/ps_core.h>
#include <ps/ps_gadget.h>

static void subroutine(void) {
   printf("subroutine called\n");
   sleep(1);
}

int main(void) {
   printf("pid: %d\n", getpid());

   void *base = ps_get_base_addr();
   printf("base addr: %p\n", base);

   struct ps_gadget_ctx ctx = {0};
   ps_gadget_build_chain(&ctx, 0, base);

   //ps_setup();

   while (1) {
      subroutine();           // call subroutine
      ps_sleep(4 * 1000);     // sleep for 4 seconds
   }
}
