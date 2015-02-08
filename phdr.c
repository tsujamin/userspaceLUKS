#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <arpa/inet.h>

#include "phdr.h"

#define hex_print(fd, len, arr) dprintf(fd, "0x"); for(int i = 0; i < len; i++) {dprintf(fd, "%x", arr[i]);}

const uint8_t LUKS_MAGIC[] =  {'L', 'U', 'K', 'S', 0xBA, 0xBE};

/*
 * Read the LUKS header from the provided file. All int fields are Little Endian
 * dev_file: path to LUKS disk file
 * hdr: PTR to luks_phdr struct to fill
 * Return: 0 on success, -1 on fail
 */
int luks_load_phdr(const char * dev_file, struct luks_phdr *hdr)
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
