/* t.c */
#include <stdio.h>
void foo() {
  int *ptr = 0;
  *ptr = 7;
}

int main() {
  foo();
  return 0;
}