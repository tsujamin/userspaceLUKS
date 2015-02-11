moduledir = lib
AM_CPPFLAGS = -std=gnu99

noinst_LTLIBRARIES = libluks.la

libluks_la_CPPFLAGS = $(AM_CPPFLAGS) -I crypto_backend
libluks_la_SOURCES = phdr.c phdr.h
libluks_la_LIBADD = crypto_backend/libcrypto_backend.la 
