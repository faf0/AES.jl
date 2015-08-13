# AES Implementation in Julia

This package implements the Advanced Encryption Standard (AES) cipher in Julia.
It supports 128-bit, 192-bit, and 256-bit keys.
Note that the implementation is not optimized with regard to performance or resistance to timing attacks.

This package also allows to use AES in the following block cipher modes of operation:

* ECB (Electronic codebook)
* CBC (Cipher-block chaining)
* CFB (Cipher feedback)
* OFB (Output feedback)
* CTR (Counter)

# Installation

Use Pkg.clone with the corresponding URL in Julia to install this package.

# Example Usage

The following code shows how to use AES in OFB mode for encryption.

~~~
using AES
key = rand(Uint8, div(256, 8))
iv = rand(Uint8, 16)
plaintext = rand(Uint8, 3 * 16)
AESOFB(plaintext, key, iv)
~~~

More examples can be found in `test/runtests.jl`.

# Contact

Feel free to report any bugs and to send pull requests.

