(in-package #:cl-user)
(defpackage #:cl-gcrypt
  (:use #:cl #:cl-gcrypt.helper))
(in-package #:cl-gcrypt)

(cffi:define-foreign-library libgcrypt
  (:darwin (:or "libgcrypt.20.dylib" "libgcrypt.dylib.20" "libgcrypt.dylib"))
  (:unix (:or "libgcrypt.so.20" "libgcrypt.20.so" "libgcrypt.so"))
  (t (:default "libgcrypt")))

(cffi:use-foreign-library libgcrypt)

(cffi:defctype #.(lispify "gcry_error_t" 'type) :uint)
(export '#.(lispify "gcry_error_t" 'type))

(defenum
    (#.(lispify "GCRYCTL_CFB_SYNC" 'enumvalue) 3)
    (#.(lispify "GCRYCTL_RESET" 'enumvalue) 4)
  (#.(lispify "GCRYCTL_FINALIZE" 'enumvalue) 5)
  (#.(lispify "GCRYCTL_TEST_ALGO" 'enumvalue) 8)
  (#.(lispify "GCRYCTL_IS_SECURE" 'enumvalue) 9)
  (#.(lispify "GCRYCTL_GET_ASNOID" 'enumvalue) 10)
  (#.(lispify "GCRYCTL_SET_CBC_CTS" 'enumvalue) 41)
  (#.(lispify "GCRYCTL_SET_SBOX" 'enumvalue) 73)
  (#.(lispify "GCRYCTL_GET_TAGLEN" 'enumvalue) 76))

(export '#.(lispify "GCRYCTL_RESET" 'enumvalue))
(export '#.(lispify "GCRYCTL_FINALIZE" 'enumvalue))
(export '#.(lispify "GCRYCTL_TEST_ALGO" 'enumvalue))
(export '#.(lispify "GCRYCTL_GET_ASNOID" 'enumvalue))
(export '#.(lispify "GCRYCTL_GET_ASNOID" 'enumvalue))
(export '#.(lispify "GCRYCTL_IS_SECURE" 'enumvalue))
(export '#.(lispify "GCRYCTL_GET_TAGLEN" 'enumvalue))
(export '#.(lispify "GCRYCTL_CFB_SYNC" 'enumvalue))
(export '#.(lispify "GCRYCTL_SET_CBC_CTS" 'enumvalue))
(export '#.(lispify "GCRYCTL_SET_SBOX" 'enumvalue))

