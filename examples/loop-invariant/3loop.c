
#include <klee/klee.h>
#include <stdio.h>

int main() {
  int x[3] = {1, 20, 3};
  while(klee_induce_invariants() & x[1]) {
    x[1] -- ;
    if (x[0] < 4) {
      printf("x[0] may be less than 4\n");
    } else {
      printf("x[0] may be more\n");
    }
    if (x[2] == 3) {
      printf("x[2] may == 3\n");
    } else {
      printf("x[2] may != 3\n");
    }
    if (x[1] < 100) {
      printf("x[1] may be less than 100.\n");
    } else {
      printf("x[1] may be more\n");
    }
  }
  klee_assert(x[2] == 3);
  printf("afterloop");
  return 0;
}
