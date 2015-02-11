/*
 * Linux kernel userspace API crypto backend implementation (skcipher)
 *
 * Copyright (C) 2012, Red Hat, Inc. All rights reserved.
 * Copyright (C) 2012-2014, Milan Broz
 *
 * This file is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This file is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this file; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>
#include <openssl/evp.h>
#include "crypto_backend.h"

struct crypt_cipher {
	EVP_CIPHER * ciph;
	unsigned char * key;
	size_t key_l;
};

struct cipher_alg {
	const char *name;
	int blocksize;
};

/* FIXME: Getting block size should be dynamic from cipher backend. */
static struct cipher_alg cipher_algs[] = {
	{ "cipher_null", 16 },
	{ "aes",         16 },
	{ "serpent",     16 },
	{ "twofish",     16 },
	{ "anubis",      16 },
	{ "blowfish",     8 },
	{ "camellia",    16 },
	{ "cast5",        8 },
	{ "cast6",       16 },
	{ "des",          8 },
	{ "des3_ede",     8 },
	{ "khazad",       8 },
	{ "seed",        16 },
	{ "tea",          8 },
	{ "xtea",         8 },
	{ NULL,           0 }
};

static struct cipher_alg *_get_alg(const char *name)
{
	int i = 0;

	while (name && cipher_algs[i].name) {
		if (!strcasecmp(name, cipher_algs[i].name))
			return &cipher_algs[i];
		i++;
	}
	return NULL;
}

int crypt_cipher_blocksize(const char *name)
{
	struct cipher_alg *ca = _get_alg(name);

	return ca ? ca->blocksize : -EINVAL;
}


/*
 *ciphers
 *
 * ENOENT - algorithm not available
 * ENOTSUP - AF_ALG family not available
 * (but cannot check specificaly for skcipher API)
 */
int crypt_cipher_init(struct crypt_cipher **ctx, const char *name,
		    const char *mode, const void *buffer, size_t length)
{
	char ciph_str[128];
	int key_len = length * 8;
	struct crypt_cipher *cc;
	EVP_CIPHER * ec;

	cc = malloc(sizeof(*cc));
	if(!cc)
		return -ENOMEM;

	if(!strcmp(mode, "xts")) // XTS key needs to be halved
		key_len /= 2;
	
	snprintf(ciph_str, 128, "%s-%d-%s", name, key_len, mode);

	ec = (EVP_CIPHER *) EVP_get_cipherbyname(ciph_str);
	if(!ec || length != EVP_CIPHER_key_length(ec))
		return -ENOTSUP;
	
	cc->ciph = ec;
	cc->key_l = length;
	cc->key = malloc(length);

	if(!cc->key)
		return -ENOMEM;

	memcpy(cc->key, buffer, length);

	*ctx = cc;

	return 0;
}

/*
 * encrypt/decrypt op
 * ENOTSUP - Bad algorithm/key combination
 * EINVAL - Malformed ciphertext
 */
int crypt_cipher_op(struct crypt_cipher *ctx,
			const char *in, char *out, size_t length,
			const char *iv, size_t iv_length, int enc)
{
	EVP_CIPHER_CTX evp_ctx;
	int xfered = 0;

	EVP_CIPHER_CTX_init(&evp_ctx);
	
	if( 	iv_length != EVP_CIPHER_iv_length(ctx->ciph) ||
	 	!EVP_CipherInit(&evp_ctx, ctx->ciph, ctx->key, 
			(unsigned char *) iv, enc))
		return -ENOTSUP;

	if( 	!EVP_CipherUpdate(&evp_ctx, (unsigned char *) out, &xfered, 
				(unsigned char *) in, length) ||
		!EVP_CipherFinal(&evp_ctx, (unsigned char *) out + xfered, &xfered))
		return -EINVAL;
	
	return 0;
}

int crypt_cipher_decrypt(struct crypt_cipher *ctx,
			 const char *in, char *out, size_t length,
			 const char *iv, size_t iv_length)
{
	return crypt_cipher_op(ctx, in, out, length, iv, iv_length, 0);

}
int crypt_cipher_encrypt(struct crypt_cipher *ctx,
			 const char *in, char *out, size_t length,
			 const char *iv, size_t iv_length)
{
	return crypt_cipher_op(ctx, in, out, length, iv, iv_length, 1);
}

int crypt_cipher_destroy(struct crypt_cipher *ctx)
{
	if(ctx->key) {
		memset(ctx->key, 0, ctx->key_l);
		free(ctx->key);
	}
	memset(ctx, 0, sizeof(*ctx));
	free(ctx);
	return 0;
}
