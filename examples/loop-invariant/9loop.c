
#include <klee/klee.h>
#include <stdio.h>


int main() {
  int x = 10;
  int y = klee_int("y");
  int z = 0;

  int i = 20;


  while (klee_induce_invariants() & i--) {

    while(klee_induce_invariants() & --x) {
      if (z == 1) {
        printf("z may be 1\n");
      } else {
        printf("z may be not 1\n");
      }
    }
    if (x == -1) printf("x may be -1\n");
  }

  printf("\n\n ----- afterloop ---- \n\n\n");
  return 0;
}
