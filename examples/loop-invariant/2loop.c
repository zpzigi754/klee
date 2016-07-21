
#include <klee/klee.h>
#include <stdio.h>

int main() {
  int x = 3;
  int y = 5;
  int z = klee_int("z");
  int w = z;
  while(klee_induce_invariants()) {
    x -- ;
    if (x < 4) {
      printf("x may be less than 4\n");
    } else {
      printf("x may be more\n");
    }
    if (y == 5) {
      printf("y may == 5\n");
    } else {
      printf("y may != 5\n");
    }
  }
  klee_assert(w == z);
  printf("afterloop");
  return 0;
}
