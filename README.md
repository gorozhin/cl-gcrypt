# cl-gcrypt

![tests](https://github.com/gorozhin/cl-gcrypt/actions/workflows/tests.yml/badge.svg)

cl-gcrypt is a Common Lisp binding for [libgcrypt](https://gnupg.org/related_software/libgcrypt/ "libgcrypt") crypto library. It currently supports hashing, symmetric encryption and asymmetric encryption as well as internal module provideing symbolic expressing capabilities.

This is really intended as a backend for a general library for general cryptography, yet to be developed.

For usage examples head towards tests in `t/`, for documentation refer to the original [one](https://gnupg.org/documentation/manuals/gcrypt/ "one").

It have been tested on 1.8-1.9 versions of libgcrypt, though it can ocassionaly work on others as well.

# Installation
Install from [Quicklisp](https://www.quicklisp.org/beta/ "Quicklisp") or [Ultralisp](https://ultralisp.org/projects/gorozhin/cl-gcrypt "Ultralisp")

For manual installation drop the source of the library to an ASDF discoverable location and list it as dependency in system's `.asd` file.

# License 
cl-gcrypt a Common Lisp bindng for libgcrypt

Copyright (C) 2021 Mikhail Gorozhin

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation; either
version 2.1 of the License, or (at your option) any later version.

This library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public
License along with this library; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
