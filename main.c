#include <stdio.h>
#include <unistd.h>
#include <eepy/eepy.h>

static void subroutine(void) {
   printf("subroutine called\n");
}

int main(void) {
   printf("pid: %d\n", getpid());

   struct eepy_ctx ctx = {0};
   if (!eepy_init(&ctx)) {
      printf("failed to initialize eepy\n");
      return(0);
   }

   while (1) {
      subroutine();           // do work
      bedtime(&ctx, 5);       // sleep
   }
}
