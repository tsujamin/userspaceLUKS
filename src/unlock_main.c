#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

#include "phdr.h"
#include "stdio.h"

int main(int argc, char * argv[])
{
    int out_fd, dev_fd, mk_len;
    char ** mk = malloc(sizeof(char *));
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

    if(!luks_get_mk(mk, &mk_len, &phdr, dev_fd))
        printf("Master key unlocked!\n");
    else 
        printf("No matching keyslots\n");

    memset(*mk, 0, phdr.keyBytes);
    return 0;
}
