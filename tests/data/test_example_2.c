#include <stdio.h>
#include <stdlib.h>

// gcc test_example_2.c -static -m32 -fno-stack-protector -o test_example_2
void initialize(int *array, int size) {
  for (int i = 0; i <= size; ++i) {
    array[i] = 0;
  }
}

int main(void) {
  int *p;
  int values[10];
  int x = 20;
  int y = 10;
  p = &x;

  *p = 37;
  initialize(values, 10);
  x = *p + y;
  return 0;
}