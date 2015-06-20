# userspaceLUKS
A fully userspace, partial implementation of LUKS.

The project aims to provide a Filesystem in UserSpace module for mounting encrypted drives using the Linux Unified Key Setup specification.

## luks_mount
Mount a decrypted copy of the filesystem using FUSE.

__DO NOT USE THIS ON REAL DATA, IT WILL MAKE IT UNUSABLE__

Implemented features:
  + Read support for the encrypted data (can be mounted via losetup/diskutil)
Partially implemented features:
  + Write support (present but appears to destroy key material)
Planned features:
  + Expose LUKS stats as file
  + Support passphrase changing
  + Some level of security

## luks_unlock
Attempts to unlock a keyslot using the provided passphrase

## luks_stats
Prints out the data stored in the LUKS header

## Building the source
Compilation from source requires the following packages

 + OpenSSL
 + FUSE
 + autoconf/automake/libtool

```bash
autoconf --install
./configure
make
sudo make install
```
## Building on OSX:
The version of OpenSSL present on OSX is missing the PKCS5_PBKDF2_HMAC, causing libcrypto_backend to not compile. As such it must be compiled against a different copy of OpenSSL, such as from Homebrew.

```bash
brew install openssl
export OPENSSL_LIBS=$(PKG_CONFIG_PATH=$(brew --prefix openssl)/lib/pkgconfig/ pkg-config --libs openssl)
export OPENSSL_CFLAGS=$(PKG_CONFIG_PATH=$(brew --prefix openssl)/lib/pkgconfig/ pkg-config --cflags openssl)
./configure
```

Alternatively you can `brew link --force openssl`.


# Acknowledgements
The current crypto libraries are provided by the [cryptsetup](https://code.google.com/p/cryptsetup/) reference implementation.
