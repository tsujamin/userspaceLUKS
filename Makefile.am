SUBDIRS = crypto_backend
bin_PROGRAMS = luks_stats luks_unlock
dist_doc_DATA = README

AM_CPPFLAGS = -I crypto_backend

luks_stats_SOURCES = stats_main.c phdr.c
luks_stats_LDADD = crypto_backend/libcrypto_backend.la

luks_unlock_SOURCES = unlock_main.c phdr.c
luks_unlock_LDADD = crypto_backend/libcrypto_backend.la
