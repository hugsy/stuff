/**
 * Q'n'd shellcode wrapper for Linux
 *
 * @_hugsy_
 */

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>


#define MAX_SC_SIZE (1<<16)

void *sc_base;

void* copy_from_file(char* filename)
{
        ssize_t n = 0;
        void *off;
        int fd;

        fd = open(filename, O_RDONLY);
        if (fd<0){
                perror("open");
                return NULL;
        }

        sc_base = mmap(NULL, MAX_SC_SIZE, PROT_READ|PROT_EXEC|PROT_WRITE,
                       MAP_SHARED|MAP_ANONYMOUS, 0, 0);
        if (sc_base == (void*) -1){
               perror("mmap");
               return NULL;
        }

        memset(sc_base, 0x00, MAX_SC_SIZE);
        off = sc_base;

        do {
                n = read(fd, off, 128);
                if (n<0) {
                        perror("read");
                        close(fd);
                        munmap(sc_base, MAX_SC_SIZE);
                        return NULL;
                }
                off += n;
        } while (n > 0);

        printf("[+] %ld bytes copied to 0x%p\n", (off-sc_base), sc_base);

        return sc_base;
}


void trigger(void)
{
        int (*func)();
        func = (int (*)()) sc_base;
        (*func)();
        munmap(sc_base, MAX_SC_SIZE);
        return;
}


int main(int argc, char **argv)
{
        if (argc != 2) {
                printf("Missing filename\n");
                return -1;
        }

        if (copy_from_file(argv[1])) {
                trigger();
                return EXIT_SUCCESS;
        } else {
                return EXIT_FAILURE;
        }

}
