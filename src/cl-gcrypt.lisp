(in-package :cl-user)
(defpackage cl-gcrypt
  (:use :cl :cl-gcrypt.helper))
(in-package :cl-gcrypt)

(cffi:define-foreign-library libgcrypt
  (:darwin (:or "libgcrypt.20.dylib" "libgcrypt.dylib.20" "libgcrypt.dylib"))
  (:unix (:or "libgcrypt.so.20" "libgcrypt.20.so" "libgcrypt.so"))
  (t (:default "libgcrypt")))

(cffi:use-foreign-library libgcrypt)
