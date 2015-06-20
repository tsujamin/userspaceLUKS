#ifndef MOUNT_FILEOPS_H
#define MOUNT_FILEOPS_H

#define FUSE_USE_VERSION 26

#include <errno.h>
#include <string.h>
#include <fuse.h>
#include <sys/stat.h>
#include <sys/disk.h>
#include <unistd.h>
#include "phdr.h"
#include "mount_main.h"

//Filesystem nodes
#define BLOCK_NODE "/disk"
#define PASS_NODE "/passphrase"
#define STAT_NODE "/stats"

int luks_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
                off_t offseet,  struct fuse_file_info *fi);

int luks_getattr(const char *path, struct stat *stbuf);

int luks_open(const char *path , struct fuse_file_info *fi);

int luks_read(const char *path, char *buf, size_t size, off_t offset,
              struct fuse_file_info *fi);

int luks_write(const char *path, const char *buf, size_t size, off_t offset,
             struct fuse_file_info *fi);


#endif
