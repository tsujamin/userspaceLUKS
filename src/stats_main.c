#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>

#include "phdr.h"
#include "stdio.h"

int main(int argc, char * argv[])
{
    int out_fd, dev_fd;
    struct luks_phdr phdr;

    if(argc < 2) {
        printf("%s: device [output]\n", argv[0]);
        return 1;
    }

    out_fd = (argc == 3) ?
        open(argv[2], O_RDWR | O_CREAT | O_EXCL) :
        STDOUT_FILENO;

    if (out_fd == -1) {
        perror("opening output file failed: ");
        return 1;
    }

    luks_init();

    if(luks_load_phdr(argv[1], &phdr, &dev_fd))
        return 1;

    luks_print_phdr(out_fd, &phdr);
    
    return 0;
}
