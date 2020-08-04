#include <stdio.h>

int factorial(int n)
{
    if (n == 1)
        return 1;
    return n * factorial(n - 1);
}

int main(int argc, char *argv[])
{
    int err = factorial(-1);
    printf("[*] -1! = %d\n", err);
}