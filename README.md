# cl-gcrypt

![tests](https://github.com/gorozhin/cl-gcrypt/actions/workflows/tests.yml/badge.svg)

cl-gcrypt is a Common Lisp binding for [libgcrypt](https://gnupg.org/related_software/libgcrypt/ "libgcrypt") crypto library. It currently supports hashing, symmetric encryption and asymmetric encryption as well as internal module provideing symbolic expressing capabilities.

This is really intended as a backend for a general library for general cryptography, yet to be developed.

For usage examples head towards tests in `t/`, for documentation refer to the original [one](https://gnupg.org/documentation/manuals/gcrypt/ "one").

It have been tested on 1.8-1.9 versions of libgcrypt, though it can ocassionaly work on others as well.

# Installation

Drop the source of the library to an ASDF discoverable location and list it as dependency in system's `.asd` file.
