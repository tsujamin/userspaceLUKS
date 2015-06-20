# userspaceLUKS
A fully userspace, partial implementation of LUKS.

The project aims to provide a Filesystem in UserSpace module for mounting encrypted drives using the Linux Unified Key Setup specification.

## luks_mount
Currently incomplete.

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


# Acknowledgements
The current crypto libraries are provided by the [cryptsetup](https://code.google.com/p/cryptsetup/) reference implementation.
