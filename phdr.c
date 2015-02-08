#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <arpa/inet.h>

#include "phdr.h"

#define hex_print(fd, len, arr) dprintf(fd, "0x"); for(int i = 0; i < len; i++) {dprintf(fd, "%x", arr[i]);}

const uint8_t LUKS_MAGIC[] =  {'L', 'U', 'K', 'S', 0xBA, 0xBE};

int openssl_init = 0;

/*
 * Read the LUKS header from the provided file. All int fields are Little Endian
 * dev_file: path to LUKS disk file
 * hdr: PTR to luks_phdr struct to fill
 * fd: pointer to integer to return FD as, can be NULL
 * Return: 0 on success, -1 on fail
 */
int luks_load_phdr(const char * dev_file, struct luks_phdr *hdr, int * fd)
{
    int dev_fd, res;

    //open and read phdr to provided struct
    if((dev_fd = open(dev_file, O_RDONLY)) == -1) {
        perror("error opening disk");
        return -1;
    }

    res = pread(dev_fd, hdr, sizeof(struct luks_phdr), 0);

    if(res == -1) {
        perror("error reading disk");
        return -1;
    } else if(res != sizeof(struct luks_phdr)) {
        printf("unable to read entire LUKS header\n");
        return -1;
    }

    //Save FD
    if(fd)
        *fd = dev_fd;

    //convert phdr int fields to LE
    hdr->version = htons(hdr->version);
    hdr->payloadOffset = htonl(hdr->payloadOffset);
    hdr->keyBytes = htonl(hdr->keyBytes);
    hdr->mkIterations = htonl(hdr->mkIterations);

    for(int i = 0; i < LUKS_NUMKEYS; i++) {
        hdr->keyslots[i].active = htonl(hdr->keyslots[i].active);
        hdr->keyslots[i].iterations = htonl(hdr->keyslots[i].iterations);
        hdr->keyslots[i].kmOffset = htonl(hdr->keyslots[i].kmOffset);
        hdr->keyslots[i].stripes = htonl(hdr->keyslots[i].stripes);
    }
    return 0;
}

/*
 * Writes a formated description of the LUKS header to an open file
 */
void luks_print_phdr(int fd, struct luks_phdr * hdr)
{
    dprintf(fd, "Magic: \"%.*s0x%x%x\"", 4, hdr->magic, hdr->magic[4], hdr->magic[5]);
    dprintf(fd, " (%s)\n", (!strncmp((const char *) hdr->magic,
                                    (const char *) LUKS_MAGIC, 6)) ?
                                    "good" : "bad");
    dprintf(fd, "Version: %hu\n", hdr->version);
    dprintf(fd, "Cipher: %s\n", hdr->cipherName);
    dprintf(fd, "Cipher Mode: %s\n", hdr->cipherMode);
    dprintf(fd, "Hash: %s\n", hdr->hashSpec);
    dprintf(fd, "Payload Offset (sectors): %d\n", hdr->payloadOffset);
    dprintf(fd, "Key Length (bytes): %d\n", hdr->keyBytes);
    dprintf(fd, "Master Key Digest: ");
    hex_print(fd, LUKS_DIGEST_SIZE, hdr->mkDigest);
    dprintf(fd, "\nMasker Key Salt: ");
    hex_print(fd, LUKS_SALT_SIZE, hdr->mkSalt);
    dprintf(fd, "\nMasker Key Iterations: %d\n", hdr->mkIterations);
    dprintf(fd, "UUID: %.*s\n", UUID_L, hdr->uuid);
    dprintf(fd, "Keyslot\tActive\tIterations\tKey Offset\tStripes\tSalt\n");

    for(int i = 0; i < LUKS_NUMKEYS; i++) {
        if(hdr->keyslots[i].active == LUKS_KEY_ENABLED) {
            dprintf(fd, "%d\t%s\t%d\t\t%d\t\t%d\t",
                i,
                "yes",
                hdr->keyslots[i].iterations,
                hdr->keyslots[i].kmOffset,
                hdr->keyslots[i].stripes);
            hex_print(fd, LUKS_SALT_SIZE, hdr->keyslots[i].salt);
            dprintf(fd, "\n");
        } else {
            dprintf(fd, "%d\tno\n", i);
        }
    }
}

/*
 * Retrieves a MK candidate from a keyslot
 * returns 1 on fail, 0 on success
 */
int luks_get_mk_cand(struct luks_phdr * hdr, int fd, int ks_num, 
                    void * mkey_cand, int mkey_len, 
                    char * passphrase, int pass_len) {
    
    assert(ks_num >=0 && ks_num <= LUKS_NUMKEYS);
    assert(passphrase && mkey_cand && hdr);
    assert(mkey_len == hdr->keyBytes);

    if(!openssl_init)
        OpenSSL_add_all_algorithms();

    struct key_slot * ks = &hdr->keyslots[ks_num];
    int ret = 0,
        split_key_len = hdr->keyBytes * ks->stripes;
    unsigned char * key_hash = malloc(hdr->keyBytes),
                  * sector_data = malloc(split_key_len);
    
    //check if active
    if(ks->active != LUKS_KEY_ENABLED)
        return 1;

    //TODO Check and exec for non SHA pbkdf2
    assert(!strcmp(hdr->hashSpec, "sha1"));

    //Hash, returns 1 on success
    ret = PKCS5_PBKDF2_HMAC_SHA1(passphrase, pass_len,
        ks->salt, LUKS_SALT_SIZE, ks->iterations,
        hdr->keyBytes, key_hash);
    
    if(!ret)
        return !ret;

    //Get split key
    if(luks_decrypt_sectors(fd, ks->kmOffset, key_hash, sector_data, split_key_len))
        return 1;

    if(AF_merge((char *) sector_data, mkey_cand, hdr->keyBytes, ks->stripes, hdr->hashSpec)< 0) 
        return 1;


    return 0;    
}

int luks_decrypt_sectors(int fd, uint64_t sector, unsigned char * key,
        unsigned char * out, int len)
{
    //TODO probably leaks ctx
    assert(sector >= 0 && out && len >=0);

    int block_size = 0;
    unsigned char * ciphertext = malloc(len),
                  * IV = malloc(EVP_CIPHER_iv_length(EVP_aes_128_xts()));
    EVP_CIPHER_CTX ctx;

    //Zero the IV and Key
    memset(IV, 0, EVP_CIPHER_iv_length(EVP_aes_128_xts()));

    //Get blocksize for read
    if(ioctl(fd, DKIOCGETBLOCKSIZE, &block_size))
        return 1;

    //Read ciphertext
    if(pread(fd, ciphertext, len, sector * block_size) != len) {
        free(ciphertext);
        return 1;
    }


    //decrypt
    int offset = 0,
	written = 0;
    while(offset < len) {
	//init ctx for this round
	EVP_CIPHER_CTX_init(&ctx);

	//Set new IV and decrypt block
	*(uint64_t *) IV = offset/block_size; //Iv offset starts at 0 for ks blocks
	if(!EVP_DecryptInit(&ctx, EVP_aes_128_xts(), key, IV))
		return 1;
	if(!EVP_DecryptUpdate(&ctx, out + offset, &written, ciphertext + offset, block_size))
		return 1; //return if either fail
        assert(written == block_size);
	offset += written;

	//Call final
	if(!EVP_DecryptFinal(&ctx, out + offset, &written))
		return 1;
	assert(written == 0); //TEST
	offset += written;
    }

    return 0;
}

int luks_get_mk(char **mk, int * mk_len, struct luks_phdr * hdr, int fd)
{
    *mk_len = hdr->keyBytes;
    char * mk_cand = malloc(*mk_len),
                  * mk_hash = malloc(LUKS_DIGEST_SIZE);
    char * passphrase;

    passphrase = getpass("Enter passphrase: ");

    for(int i = 0; i < LUKS_NUMKEYS; i++) {
        if(luks_get_mk_cand(hdr, fd, i, mk_cand, *mk_len, passphrase,
                    strlen(passphrase)))
            continue;
         //Hash, returns 1 on success
        if(!PKCS5_PBKDF2_HMAC_SHA1(mk_cand, *mk_len,
            hdr->mkSalt, LUKS_SALT_SIZE, hdr->mkIterations,
            LUKS_DIGEST_SIZE, (unsigned char *) mk_hash))
            return 1; //fail

        if(!strncmp(mk_hash, (char * ) hdr->mkDigest, LUKS_DIGEST_SIZE)) {
            *mk = mk_cand;
            return 0;
        }      
    }
    return 1;
}
