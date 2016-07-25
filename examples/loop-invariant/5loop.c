
#include <klee/klee.h>
#include <stdio.h>

struct A {
  int x;
  int y;
};

struct SubArr {
  struct A val[100];
};

int main() {
  struct SubArr sas[20] = {{{0,0}}};
  int idx1 = klee_int("idx");
  int idx2 = klee_int("idx");
  klee_assume(0 <= idx1);
  klee_assume(idx1 < 5);
  klee_assume(0 <= idx2);
  klee_assume(idx2 < 5);

  sas[idx1].val[idx2].x = 15;

  klee_assert(sas[idx1].val[3].y == 0);

  struct A x[4] = {{1,1}, {2, 2}, {3, 3}, {4, 4}};
  while(klee_induce_invariants() & x[1].x) {
    int idx = x[1].x;//2, 1, 0
    klee_assume(0 <= idx);
    klee_assume(idx < 3);
    x[idx].y = 0;
    --idx;
    x[1].x = idx;

    if (x[3].y == 4) {
      printf("x[3] may be 4.\n");
    } else {
      printf("x[3] may be NOT 4.\n");
    }
  }//x={{1,0}, {0, 0}, {3, 0}, {4, 4}};
  klee_assert(x[3].x == 4);
  printf("afterloop");
  return 0;
}
