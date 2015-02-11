bin_PROGRAMS = luks_stats luks_unlock luks_mount
AM_CPPFLAGS = -std=gnu99 -I ../lib

luks_stats_SOURCES = stats_main.c
luks_stats_LDADD = ../lib/libluks.la

luks_unlock_SOURCES = unlock_main.c
luks_unlock_LDADD = ../lib/libluks.la

luks_mount_SOURCES = mount_main.c 
luks_mount_LDADD = $(FUSE_LIBS) ../lib/libluks.la
luks_mount_CFLAGS = $(FUSE_CFLAGS)

