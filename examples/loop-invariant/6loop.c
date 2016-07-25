
#include <klee/klee.h>
#include <stdio.h>


int main() {
  int x = 10;
  int y = klee_int("y");
  int z = 0;

  if (5 < y) {
    z = 1;
    printf("taking this one");
  } else {
    z = 2;
    printf("taking OTHER one");
  }

  while(klee_induce_invariants() & x--) {
    if (z == 1) {
      printf("z may be 1\n");
    } else {
      printf("z may be not 1\n");
    }
  }

  if (z == 3) {
    printf("at the end, z may be 3, who knows\n");
  }

  printf("afterloop\n");
  return 0;
}
