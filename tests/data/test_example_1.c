// gcc test_example_1.c -o test_example_1

void h(int *r) {
  *r = 10;  // crash!!
}
void g(int *q) {
  int *t = q;
  h(t);
}
void foo() {
  int *p = 0;  // Null value assigned
  g(p);
}
int main() {
  foo();
  return 0;
}