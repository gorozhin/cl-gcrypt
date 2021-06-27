(in-package :cl-gcrypt)

(cffi:defctype #.(lispify "gcry_cipher_hd_t" 'type) :pointer)

(defenum
  #.(lispify "GCRY_CIPHER_NONE" 'enumvalue)
  #.(lispify "GCRY_CIPHER_IDEA" 'enumvalue)
  #.(lispify "GCRY_CIPHER_3DES" 'enumvalue)
  #.(lispify "GCRY_CIPHER_CAST5" 'enumvalue)
  #.(lispify "GCRY_CIPHER_BLOWFISH" 'enumvalue)
  #.(lispify "GCRY_CIPHER_SAFER_SK128" 'enumvalue)
  #.(lispify "GCRY_CIPHER_DES_SK" 'enumvalue)
  #.(lispify "GCRY_CIPHER_AES" 'enumvalue)
  #.(lispify "GCRY_CIPHER_AES192" 'enumvalue)
  #.(lispify "GCRY_CIPHER_AES256" 'enumvalue)
  #.(lispify "GCRY_CIPHER_TWOFISH" 'enumvalue)
  (#.(lispify "GCRY_CIPHER_ARCFOUR" 'enumvalue) 301)
  #.(lispify "GCRY_CIPHER_DES" 'enumvalue)
  #.(lispify "GCRY_CIPHER_TWOFISH128" 'enumvalue)
  #.(lispify "GCRY_CIPHER_SERPENT128" 'enumvalue)
  #.(lispify "GCRY_CIPHER_SERPENT192" 'enumvalue)
  #.(lispify "GCRY_CIPHER_SERPENT256" 'enumvalue)
  #.(lispify "GCRY_CIPHER_RFC2268_40" 'enumvalue)
  #.(lispify "GCRY_CIPHER_RFC2268_128" 'enumvalue)
  #.(lispify "GCRY_CIPHER_SEED" 'enumvalue)
  #.(lispify "GCRY_CIPHER_CAMELLIA128" 'enumvalue)
  #.(lispify "GCRY_CIPHER_CAMELLIA192" 'enumvalue)
  #.(lispify "GCRY_CIPHER_CAMELLIA256" 'enumvalue)
  #.(lispify "GCRY_CIPHER_SALSA20" 'enumvalue)
  #.(lispify "GCRY_CIPHER_SALSA20R12" 'enumvalue)
  #.(lispify "GCRY_CIPHER_GOST28147" 'enumvalue)
  #.(lispify "GCRY_CIPHER_CHACHA20" 'enumvalue))

(defenum
  #.(lispify "GCRY_CIPHER_MODE_NONE" 'enumvalue)
  #.(lispify "GCRY_CIPHER_MODE_ECB" 'enumvalue)
  #.(lispify "GCRY_CIPHER_MODE_CFB" 'enumvalue)
  #.(lispify "GCRY_CIPHER_MODE_CBC" 'enumvalue)
  #.(lispify "GCRY_CIPHER_MODE_STREAM" 'enumvalue)
  #.(lispify "GCRY_CIPHER_MODE_OFB" 'enumvalue)
  #.(lispify "GCRY_CIPHER_MODE_CTR" 'enumvalue)
  #.(lispify "GCRY_CIPHER_MODE_AESWRAP" 'enumvalue)
  #.(lispify "GCRY_CIPHER_MODE_CCM" 'enumvalue)
  #.(lispify "GCRY_CIPHER_MODE_GCM" 'enumvalue)
  #.(lispify "GCRY_CIPHER_MODE_POLY1305" 'enumvalue)
  #.(lispify "GCRY_CIPHER_MODE_OCB" 'enumvalue)
  #.(lispify "GCRY_CIPHER_MODE_CFB8" 'enumvalue)
  #.(lispify "GCRY_CIPHER_MODE_XTS" 'enumvalue))

(cffi:defcfun #.(lispify "gcry_cipher_open" 'function)
  #.(lispify "gcry_error_t" 'type)
  "Create a handle for algorithm ALGO to be used in MODE. FLAGS may
be given as an bitwise OR of the gcry_cipher_flags values."
  (handle :pointer gcry_cipher_hd_t)
  (algo :int)
  (mode :int)
  (flags :uint))

(cffi:defcfun #.(lispify "gcry_cipher_close" 'function)
  :void
  "Close the cipher handle HANDLE and release all resource."
  (handle #.(lispify "gcry_cipher_hd_t" 'type)))

(cffi:defcfun #.(lispify "gcry_cipher_setkey" 'function)
  #.(lispify "gcry_error_t" 'type)
  "Set KEY of length KEYLEN bytes for the cipher handle HANDLE."
  (handle #.(lispify "gcry_cipher_hd_t" 'type))
  (key :pointer)
  (keylen :size))

(cffi:defcfun #.(lispify "gcry_cipher_encrypt" 'function)
  #.(lispify "gcry_error_t" 'type)
  "Encrypt the plaintext of size INLEN in IN using the cipher handle HANDLE
into the buffer OUT which has an allocated length of OUTSIZE. For
most algorithms it is possible to pass NULL for in and 0 for INLEN
and do a in-place decryption of the data provided in OUT."
  (handle #.(lispify "gcry_cipher_hd_t" 'type))
  (out :pointer)
  (outsize :size)
  (in :pointer)
  (inlen :size))

(cffi:defcfun #.(lispify "gcry_cipher_decrypt" 'function)
  #.(lispify "gcry_error_t" 'type)
  #.(format nil
	    "The counterpart to ~a."
	    '#.(lispify "gcry_cipher_encrypt" 'function))
  (handle #.(lispify "gcry_cipher_hd_t" 'type))
  (out :pointer)
  (outsize :size)
  (in :pointer)
  (inlen :size))

(cffi:defcfun #.(lispify "gcry_cipher_get_algo_keylen" 'function)
  :size
  "Retrieve the key length in bytes used with algorithm ALGO."
  (algo :int))

(cffi:defcfun #.(lispify "gcry_cipher_get_algo_blklen" 'function)
  :size
  "Retrieve the block length in bytes used with algorithm ALGO."
  (algo :int))

(cffi:defcfun #.(lispify "gcry_cipher_algo_name" 'function)
  :string
  "Map the cipher algorithm whose ID is contained in ALGO to a
string representation of the algorithm name.  For unknown algorithm
IDs this function returns \"?\"."
  (algo :int))

(cffi:defcfun #.(lispify "gcry_cipher_map_name" 'function)
  :int
  "Map the algorithm name NAME to an cipher algorithm ID.
Return 0 if the algorithm name is not known."
  (name :string))

(cffi:defcfun #.(lispify "gcry_cipher_mode_from_oid" 'function)
  :int
  "Given an ASN.1 object identifier in standard IETF dotted decimal
format in STRING, return the encryption mode associated with that
OID or 0 if not known or applicable."
  (string :string))

(cffi:defcfun #.(lispify "gcry_cipher_info" 'function)
  #.(lispify "gcry_error_t" 'type)
  "Retrieve various information about the cipher object HANDLE."
  (handle #.(lispify "gcry_cipher_hd_t" 'type))
  (what :int)
  (buffer :pointer)
  (nbytes :pointer))

(cffi:defcfun #.(lispify "gcry_cipher_algo_info" 'function)
  #.(lispify "gcry_error_t" 'type)
  "Retrieve various information about the cipher algorithm ALGO."
  (algo :int)
  (what :int)
  (buffer :pointer)
  (nbytes :pointer))

(defun #.(lispify "gcry_cipher_test_algo" 'function) (algo)
  "Return 0 if the algorithm ALGO is available for use."
  (#.(lispify "gcry_cipher_algo_info" 'function)
     algo
     #.(lispify "GCRYCTL_TEST_ALGO" 'enumvalue)
     (cffi:null-pointer)
     (cffi:null-pointer)))

(cffi:defcfun #.(lispify "gcry_cipher_ctl" 'function)
  #.(lispify "gcry_error_t" 'type)
  "Perform various operations on the cipher object HANDLE."
  (handle #.(lispify "gcry_cipher_hd_t" 'type))
  (cmd :int)
  (buffer :pointer)
  (buflen :size))

(defun #.(lispify "gcry_cipher_reset" 'function) (handle)
  "Reset the handle to the state after open."
  (#.(lispify "gcry_cipher_ctl" 'function)
     handle
     +gcryctl-reset+
     (cffi:null-pointer)
     0))

(cffi:defcfun #.(lispify "gcry_cipher_setiv" 'function)
  #.(lispify "gcry_error_t" 'type)
  "Set initialization vector IV of length IVLEN for the cipher handle HANDLE."
  (handle #.(lispify "gcry_cipher_hd_t" 'type))
  (iv :pointer)
  (ivlen :size))

(cffi:defcfun #.(lispify "gcry_cipher_gettag" 'function)
  #.(lispify "gcry_error_t" 'type)
  "Get authentication tag for AEAD modes/ciphers."
  (handle #.(lispify "gcry_cipher_hd_t" 'type))
  (outtag :pointer)
  (taglen :size))

(cffi:defcfun #.(lispify "gcry_cipher_authenticate" 'function)
  #.(lispify "gcry_error_t" 'type)
  "Provide additional authentication data for AEAD modes/ciphers."
  (handle #.(lispify "gcry_cipher_hd_t" 'type))
  (abuf :pointer)
  (abuflen :size))

(cffi:defcfun #.(lispify "gcry_cipher_checktag" 'function)
  #.(lispify "gcry_error_t" 'type)
  "Check authentication tag for AEAD modes/ciphers."
  (handle #.(lispify "gcry_cipher_hd_t" 'type))
  (intag :pointer)
  (taglen :size))

(defun #.(lispify "gcry_cipher_final" 'function) (a)
  "Indicate to the encrypt and decrypt functions that the
next call provides the final data.  Only used with some modes."
  (#.(lispify "gcry_cipher_ctl" 'funcation)
     a
     #.(lispify "GCRYCTL_FINALIZE" 'enumvalue)
     (cffi:null-pointer)
     0))

(cffi:defcfun #.(lispify "gcry_cipher_setctr" 'function)
  #.(lispify "gcry_error_t" 'type)
  "Set counter for CTR mode.  (CTR,CTRLEN) must denote a buffer of
block size length, or (NULL,0) to set the CTR to the all-zero block."
  (handle #.(lispify "gcry_cipher_hd_t" 'type))
  (ctr :pointer)
  (ctrlen :size))

(defun #.(lispify "gcry_cipher_sync" 'function) (handle)
  "Perform the OpenPGP sync operation if this is enabled 
for the cipher handle HANDLE."
  (#.(lispify "gcry_cipher_ctl" 'function)
     handle
     #.(lispify "GCRYCTL_CFB_SYNC" 'enumvalue)
     (cffi:null-pointer)
     0))

(defun #.(lispify "gcry_cipher_cts" 'function) (handle on)
  "Enable or disable CTS in future calls to gcry_encrypt(). CBC mode only."
  (#.(lispify "gcry_cipher_ctl" 'function)
     handle
     #.(lispify "GCRYCTL_SET_CBC_CTS" 'enumvalue)
     (cffi:null-pointer)
     on))
    
(defun #.(lispify "gcry_cipher_set_sbox" 'function) (handle oid)
  (#.(lispify "gcry_cipher_ctl" 'function)
     handle
     #.(lispify "GCRYCTL_SET_SBOX" 'enumvalue)
     oid
     0))
