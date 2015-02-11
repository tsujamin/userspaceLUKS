moduledir = lib/cryptsetup

noinst_LTLIBRARIES = libcrypto_backend.la

libcrypto_backend_la_CFLAGS = $(OPENSSL_CFLAGS) -Wall -Wno-deprecated
libcrypto_backend_la_LIBADD = $(OPENSSL_LIBS)
libcrypto_backend_la_SOURCES = crypto_backend.h af.h \
	crypto_cipher_openssl.c crypto_storage.c pbkdf_check.c crc32.c af.c

libcrypto_backend_la_SOURCES += crypto_openssl.c

AM_CPPFLAGS = -include config.h -I$(top_dir)
