SUBDIRS = crypto_backend
bin_PROGRAMS = luks_stats luks_unlock luks_mount
dist_doc_DATA = README

AM_CPPFLAGS = -std=gnu99 -I crypto_backend

luks_stats_SOURCES = stats_main.c phdr.c
luks_stats_LDADD = crypto_backend/libcrypto_backend.la

luks_unlock_SOURCES = unlock_main.c phdr.c
luks_unlock_LDADD = crypto_backend/libcrypto_backend.la

luks_mount_SOURCES = mount_main.c phdr.c
luks_mount_LDADD = $(FUSE_LIBS) crypto_backend/libcrypto_backend.la
luks_mount_CFLAGS = $(FUSE_CFLAGS)

