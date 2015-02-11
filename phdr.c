#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <arpa/inet.h>

#include "phdr.h"

#define hex_print(fd, len, arr) dprintf(fd, "0x"); for(int i = 0; i < len; i++) {dprintf(fd, "%x", arr[i]);}
#define SECTOR_SIZE 512 //Hardcoded in crypto_service

const uint8_t LUKS_MAGIC[] =  {'L', 'U', 'K', 'S', 0xBA, 0xBE};

int openssl_init = 0;


/*
 * Initialiser for LUKS functions
 */
void luks_init()
{
    crypt_backend_init(0);
}

/*
 * Read the LUKS header from the provided file. All int fields are Little Endian
 * dev_file: path to LUKS disk file
 * hdr: PTR to luks_phdr struct to fill
 * fd: pointer to integer to return FD as, can be NULL
 * Return: 0 on success, 1 on fail
 */
int luks_load_phdr(const char * dev_file, struct luks_phdr *hdr, int * fd)
{
    int dev_fd, res;

    //open and read phdr to provided struct
    if((dev_fd = open(dev_file, O_RDWR)) == -1) {
        perror("error opening disk\n");
        return -1;
    }

    res = pread(dev_fd, hdr, sizeof(struct luks_phdr), 0);

    if(res == -1) {
        perror("error reading disk\n");
        return 1;
    } else if(res != sizeof(struct luks_phdr)) {
        printf("unable to read entire LUKS header\n");
        return 1;
    } else if(strncmp((const char *) hdr->magic, (const char *) LUKS_MAGIC, MAGIC_L)) {
        printf("not a LUKS volume\n");
        return 1;
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

    struct key_slot * ks = &hdr->keyslots[ks_num];
    int ret = 0,
        split_key_len = hdr->keyBytes * ks->stripes;
    char    * key_hash = malloc(hdr->keyBytes),
            * sector_data = malloc(split_key_len);
    
    //check if active
    if(ks->active != LUKS_KEY_ENABLED)
        return 1;

    //Hash, returns 1 on success
    if(crypt_pbkdf("pbkdf2", hdr->hashSpec,
            passphrase, pass_len,
            (char *) ks->salt, LUKS_SALT_SIZE,
            key_hash, hdr->keyBytes,
            ks->iterations)) {
        ret = 1;
        goto end;
    }

    //Get split key
    if(luks_decrypt_sectors(hdr, fd, ks->kmOffset, ks->kmOffset, key_hash, sector_data, split_key_len)) {
        ret = 1;
        goto end;
    }
    
    if(AF_merge((char *) sector_data, mkey_cand, hdr->keyBytes, ks->stripes, hdr->hashSpec)< 0) {
        ret = 1;
        goto end;
    }

end:
    free(key_hash);
    free(sector_data);
    return ret;    
}

/*
 * Performs an encryption operation inplace
 * hdr: header of drive we are encrypting for
 * iv_sector: effective sector to generate IV's from
 * key: key buffer to use
 * out: buffer to read/write
 * len: length of buffer to operate on
 * enc: if true then encryption operation
 */
int luks_encop(struct luks_phdr * hdr, 
        uint64_t sector, char * key, 
        char * buf, int len, int enc)
{
    assert(sector >=0 && buf && len >=0);

    int block_size = 0,
        ret = 0;
    struct crypt_storage ** ctx = malloc(sizeof(*ctx));
    int (*op)(struct crypt_storage *, uint64_t, size_t, char *) = enc ?
        crypt_storage_encrypt : crypt_storage_decrypt;

    //get a cryptostorage struct
    //we set the start sector as sector we want to read minus where the
    //section starts, ie reading key material 2 sectors into a keyblock
    //starting at 8 would pass 10-8=2
    if(crypt_storage_init(ctx, sector,
                hdr->cipherName, hdr->cipherMode,
                key, hdr->keyBytes)) {
        ret = 1;
        goto end;
    }

    if(op(*ctx, sector, len / SECTOR_SIZE, buf)) {
        crypt_storage_destroy(*ctx);
        ret = 1;
        goto end;
    }

end:
    free(ctx);

    return ret;
}

/*
 * Decrypts sectors and returns
 * hdr: header of drive we are encrypting for
 * fd: file descriptor of enc'd drive
 * sector: sector to read from
 * iv_offset: value to sub from sector to get correct IV
 * key: key buffer to use
 * out: buffer to write
 * len: length of data to read
 */
int luks_decrypt_sectors(struct luks_phdr * hdr, int fd, 
        uint64_t sector, uint64_t iv_offset, 
        char * key, char * out, int len)
{
    //Read the cipgertext
    if(pread(fd, out, len, sector*SECTOR_SIZE) != len) 
        return 1;
    

    //Decrypt the ciphertext
    return luks_encop(hdr, sector - iv_offset, key, out, len, 0);
}

/*
 * Encrypts data and writes to sectors
 * hdr: header of drive we are encrypting for
 * fd: file descriptor of enc'd drive
 * sector: sector to write to
 * iv_offset: value to sub from sector to get correct IV
 * key: key buffer to use
 * out: buffer to read
 * len: length of data to read
 */
int luks_encrypt_sectors(struct luks_phdr * hdr, int fd, 
        uint64_t sector, uint64_t iv_offset, 
        char * key, char * in, int len)
{
    //copy the data to be encrypted incase the user still needs it
    char * enc_buff = malloc(len);
    int ret = 0;
    memcpy(enc_buff, in, len);
    if(!enc_buff)
        return 1;

    //encrypt
    if(luks_encop(hdr, sector - iv_offset, key, enc_buff, len, 1)) {
        ret = 1;
        goto end;
    }

    //Write to sectors
    if(pwrite(fd, enc_buff, len, sector) != len) {
        ret = 1;
        goto end;
    }

end:
    free(enc_buff);
    return ret;

}

int luks_get_mk(char **mk, int * mk_len, struct luks_phdr * hdr, int fd)
{
    *mk_len = hdr->keyBytes;
    int ret = 1;
    char * mk_cand = malloc(*mk_len),
         * mk_hash = malloc(LUKS_DIGEST_SIZE);
    char * passphrase;
    
    passphrase = getpass("Enter passphrase: ");

    if(!(mk_cand && mk_hash)) 
        goto end;
    


    for(int i = 0; i < LUKS_NUMKEYS; i++) {
        if(luks_get_mk_cand(hdr, fd, i, mk_cand, *mk_len, passphrase,
                    strlen(passphrase)))
            continue;
         //Hash, returns 1 on success
        if(crypt_pbkdf("pbkdf2", hdr->hashSpec,
                    mk_cand, *mk_len,
                    (char *) hdr->mkSalt, LUKS_SALT_SIZE,
                    mk_hash, LUKS_DIGEST_SIZE,
                    hdr->mkIterations)) 
            goto end_fail;
        

        if(!strncmp(mk_hash, (char * ) hdr->mkDigest, LUKS_DIGEST_SIZE)) {
            ret = 0;
            *mk = mk_cand;
            goto end;
        }      
    }

end_fail:
    free(mk_cand);
end:
    memset(passphrase, 0, strlen(passphrase));
    free(passphrase);
    free(mk_hash);

    return ret;
}
