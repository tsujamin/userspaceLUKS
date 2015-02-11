#define FUSE_USE_VERSION 26

#include <fuse.h>
#include <stdio.h>
#include <stdlib.h>

#include "phdr.h"

//Globals
struct luks_private {
    int device_fd, mk_len;
    struct luks_phdr hdr;
    char ** mk;
};

struct fuse_operations luks_oper = {
//    .read = luks_read,
//    .write = luks_write
};

int main(int argc, char * argv[])
{
    char * device_path;
    struct luks_private private;

    if(argc < 3) {
        printf("%s: [FUSE OPTIONS] DEVICE MOUNTPOINT\n",
                argv[0]);
        return 1;
    }

    //Get the device path and remove it from the arglist
    device_path = argv[argc-2];
    argv[argc-2] = argv[argc-1];
    argv[argc-1] = NULL;
    argc--;

    luks_init();

    //Open the device and get the header
    if(luks_load_phdr(device_path, &private.hdr, &private.device_fd)) 
        return 1;

    //Get the MK
    private.mk = malloc(sizeof(*private.mk));
    if(luks_get_mk(private.mk, &private.mk_len, &private.hdr, private.device_fd)) {
        printf("Invalid passphrase\n");
        return 1;
    }


   return 0; 

}
