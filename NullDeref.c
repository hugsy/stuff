#include <windows.h>
#include <stdio.h>


int main()
{
    int *p;
    //VirtualAlloc((void*)0x10, 0x1000, MEM_COMMIT, PAGE_READWRITE);
    p = 0x00;
    *p = 0x42;
    printf("I should never be here!\n");
    return -1;
}