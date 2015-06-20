#include "mount_fileops.h"

int luks_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
                off_t offseet,  struct fuse_file_info *fi)
{
    char pass_node_buf[16]; //Buffer for passphrase file names

    //only one folder (root)
    if(strcmp(path, "/") != 0)
        return -ENOENT;

    //Fill known direnties
    filler(buf, ".", NULL, 0);
    filler(buf, "..", NULL, 0);
    filler(buf, BLOCK_NODE + 1, NULL, 0);
    filler(buf, STAT_NODE + 1, NULL, 0);

    for(int i = 0; i < LUKS_NUMKEYS; i++) {
        sprintf(pass_node_buf, "%s%d", PASS_NODE + 1, i);
        filler(buf, pass_node_buf, NULL, 0);
    }

    return 0;
}

int luks_getattr(const char *path, struct stat *stbuf)
{
    memset(stbuf, 0, sizeof(struct stat));
    struct luks_private *private = fuse_get_context()->private_data;


    if(strcmp(path, "/") == 0) {
        stbuf->st_mode = S_IFDIR | 0700;
    } else if(strcmp(path, BLOCK_NODE) == 0) {
        uint64_t block_count;
        uint32_t block_size;
        stbuf->st_mode = S_IFREG | 0600;

        /*
            Block size is determined by seeking the file, dividing the length in
            bytes by the fixed sector size (see phdr.c) and subtracting the
            payload offset.
        */
        ioctl(private->device_fd, DKIOCGETBLOCKSIZE, &block_size);
        ioctl(private->device_fd, DKIOCGETBLOCKCOUNT, &block_count);


        stbuf->st_blocks = (block_size * block_count / 512);
        stbuf->st_blocks -= private->hdr.payloadOffset;
        stbuf->st_blksize = 512; //see phdr.c
        stbuf->st_size = stbuf->st_blocks * stbuf->st_blksize;
    } else if(strcmp(path, STAT_NODE) == 0) {
        stbuf->st_mode = S_IFREG | 0400;
    } else if(strncmp(path, PASS_NODE, strlen(PASS_NODE)) == 0) {
        stbuf->st_mode = S_IFREG | 0200;
    } else {
        return -ENOENT;
    }

    //Set owner/group to mounter
    stbuf->st_uid = getuid();
    stbuf->st_gid = getgid();

    return 0;
}

int luks_open (const char *path , struct fuse_file_info *fi)
{
    if( strcmp(path, BLOCK_NODE) == 0 ||
        strcmp(path, STAT_NODE) == 0 ||
        strncmp(path, PASS_NODE, strlen(PASS_NODE))) {
            return 0;
    } else {
        return -ENOENT;
    }

}

int luks_read(const char *path, char *buf, size_t size, off_t offset,
              struct fuse_file_info *fi)
{
    if(strcmp(path, BLOCK_NODE) == 0) {
        struct luks_private *private = fuse_get_context()->private_data;
        pread(private->device_fd, buf, size, offset);
        return size;
    }

    return -ENOENT;
}
