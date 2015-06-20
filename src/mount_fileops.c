#include "mount_fileops.h"
#define encrypt(luks_private, sector, buf, len) luks_encrypt_sectors( \
                     &luks_private->hdr, luks_private->device_fd, \
                     sector, luks_private->hdr.payloadOffset, \
                     *luks_private->mk, buf, len)
#define decrypt(luks_private, sector, buf, len)  luks_decrypt_sectors( \
                     &luks_private->hdr, luks_private->device_fd, \
                     sector, luks_private->hdr.payloadOffset, \
                     *luks_private->mk, buf, len)

int crypt_read(char * buf, size_t size, off_t offset)
{
    struct luks_private *private = fuse_get_context()->private_data;
    char *dec_buf = malloc(512);
    uint64_t sector = offset/512 + private->hdr.payloadOffset;
    size_t size_read = 0;

    //Decrypt first non-block sized sector, IV offset is start of payload
    if(decrypt(private, sector, dec_buf, 512 - (offset % 512)))
        goto encrypt_ret;

    sector++;
    size_read += 512 - (offset % 512);
    memcpy(buf, dec_buf, size_read);

    //Read middle blocks
    while(size_read < (size & ~0x1FF)) { //TODO check
        if(decrypt(private, sector, dec_buf, 512))
            goto encrypt_ret;

        sector++;
        memcpy(buf + size_read, dec_buf, 512);
        size_read += 512;
    }

    //decrypt last, non-block sized sector
    if(size % 512) {
        if(decrypt(private, sector, dec_buf, size % 512))
            goto encrypt_ret;

        memcpy(buf + size_read, dec_buf, size % 512);
        size_read += size % 512;
    }

encrypt_ret:
    memset(dec_buf, 0, 512);
    free(dec_buf);
    return size_read;
}

//TODO When data is saved at start offset 0, key material is destroyed (salt)
int crypt_write(const char * buf, size_t size, off_t offset)
{
    struct luks_private *private = fuse_get_context()->private_data;
    char *enc_buf = malloc(512);
    uint64_t sector = offset/512 + private->hdr.payloadOffset;
    size_t size_written = 0;

    //load first buffer (incase need be overwritten)
    if(crypt_read(enc_buf, 512, offset/512) != 512)
        goto decrypt_ret;

    //load first buffer into existing block and write to disk
    memcpy(enc_buf + (offset % 512), buf, 512 - (offset % 512));
    if(encrypt(private, sector, enc_buf, 512))
        goto decrypt_ret;

    sector++;
    size_written += 512 - (offset % 512);

    //write centre blocks
    while(size_written < (size & ~0x1FF)) {
        memcpy(enc_buf, buf + size_written, 512);
        if(encrypt(private, sector, enc_buf, 512))
            goto decrypt_ret;

        sector++;
        size_written += 512;
    }

    //Write final block if size isn't multiple of block size
    if(size % 512) {
        if(crypt_read(enc_buf, 512, offset/512) != 512)
            goto decrypt_ret;
        memcpy(enc_buf, buf + size_written, size % 512);

        if(encrypt(private, sector, enc_buf, 512))
            goto decrypt_ret;

        size_written += size % 512;
    }

decrypt_ret:
    memset(enc_buf, 0, 512);
    free(enc_buf);
    return size_written;
}

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
        return crypt_read(buf, size, offset);
    }

    return -ENOENT;
}

int luks_write(const char *path, const char *buf, size_t size, off_t offset,
               struct fuse_file_info *fi)
{
    if(strcmp(path, BLOCK_NODE) == 0) {
        return crypt_write(buf, size, offset);
    }

    return -ENOENT;
}
