
#include <klee/klee.h>
#include <stdio.h>


int main() {
  int x = 10;
  int y = klee_int("y");
  int z = 0;

  if (5 < y) {
    z = 1;
    printf("taking this one\n");
  } else {
    z = 2;
    for (int i = 0; i < 10000; ++i);
    printf("taking OTHER one\n");
  }

  while(klee_induce_invariants() & x--) {
    if (z == 1) {
      printf("z may be 1\n");
    } else {
      printf("z may be not 1\n");
    }
  }

  printf("\n\n ----- afterloop ---- \n\n\n");
  return 0;
}
