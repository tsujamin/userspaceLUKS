#ifndef PHDR_H
#define PHDR_H

#include <assert.h>
#include <stdint.h>

//Field lengths
#define MAGIC_L 6
#define CIPHNAME_L 32
#define CIPHMODE_L 32
#define HASHSPEC_L 32
#define UUID_L 40

//Constants
extern const uint8_t LUKS_MAGIC[];
#define LUKS_DIGEST_SIZE 20
#define LUKS_SALT_SIZE 32
#define LUKS_NUMKEYS 8
#define LUKS_KEY_DISABLED 0x000DEAD
#define LUKS_KEY_ENABLED 0x00AC71F3
#define LUKS_PHDR_SIZE 592

struct luks_phdr {
        uint8_t magic[MAGIC_L];
        uint16_t version;
        char cipherName[CIPHNAME_L];
        char cipherMode[CIPHMODE_L];
        char hashSpec[HASHSPEC_L];
        uint32_t payloadOffset;
        uint32_t keyBytes;
        uint8_t mkDigest[LUKS_DIGEST_SIZE];
        uint8_t mkSalt[LUKS_SALT_SIZE];
        uint32_t mkIterations;
        char uuid[UUID_L];
        struct {
            uint32_t active;
            uint32_t iterations;
            uint8_t salt[LUKS_SALT_SIZE];
            uint32_t kmOffset;
            uint32_t stripes;
        } keyslots[LUKS_NUMKEYS];
};
//assert(sizeof(struct luks_phdr) == LUKS_PHDR_SIZE);

int luks_load_phdr(const char * dev_file, struct luks_phdr *hdr);

void luks_print_phdr(int fd, struct luks_phdr * hdr);
#endif /* PHDR_H */
