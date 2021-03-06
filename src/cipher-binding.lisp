(in-package #:cl-gcrypt)

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
  #.(lispify "GCRY_CIPHER_CHACHA20" 'enumvalue)
  #.(lispify "GCRY_CIPHER_GOST28147_MESH" 'enumvalue)
  #.(lispify "GCRY_CIPHER_SM4" 'enumvalue))

(defconstant
    #.(lispify "GCRY_CIPHER_AES128" 'enumvalue)
  #.(lispify "GCRY_CIPHER_AES" 'enumvalue))

(defconstant
    #.(lispify "GCRY_CIPHER_RIJNDAEL" 'enumvalue)
  #.(lispify "GCRY_CIPHER_AES" 'enumvalue))

(defconstant
    #.(lispify "GCRY_CIPHER_RIJNDAEL128" 'enumvalue)
  #.(lispify "GCRY_CIPHER_AES128" 'enumvalue))

(defconstant
    #.(lispify "GCRY_CIPHER_RIJNDAEL192" 'enumvalue)
  #.(lispify "GCRY_CIPHER_AES192" 'enumvalue))

(defconstant
    #.(lispify "GCRY_CIPHER_RIJNDAEL256" 'enumvalue)
  #.(lispify "GCRY_CIPHER_AES256" 'enumvalue))

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
  #.(lispify "GCRY_CIPHER_MODE_XTS" 'enumvalue)
  #.(lispify "GCRY_CIPHER_MODE_EAX" 'enumvalue))

(defenum
  (#.(lispify "GCRY_CIPHER_SECURE" 'enumvalue) 1)
  (#.(lispify "GCRY_CIPHER_ENABLE_SYNC" 'enumvalue) 2)
  (#.(lispify "GCRY_CIPHER_CBC_CTS" 'enumvalue) 4)
  (#.(lispify "GCRY_CIPHER_CBC_MAC" 'enumvalue) 8))

(defenum
  (#.(lispify "GCRY_GCM_BLOCK_LEN" 'enumvalue) 16)
  (#.(lispify "GCRY_CCM_BLOCK_LEN" 'enumvalue) 16)
  (#.(lispify "GCRY_OCB_BLOCK_LEN" 'enumvalue) 16)
  (#.(lispify "GCRY_XTS_BLOCK_LEN" 'enumvalue) 16))

(cffi:defcfun #.(namify-function-definition "gcry_cipher_open")
  #.(lispify "gcry_error_t" 'type)
  "Create a handle for algorithm ALGO to be used in MODE. FLAGS may
be given as an bitwise OR of the gcry_cipher_flags values."
  (handle :pointer gcry_cipher_hd_t)
  (algo :int)
  (mode :int)
  (flags :uint))

(cffi:defcfun #.(namify-function-definition "gcry_cipher_close")
  :void
  "Close the cipher handle HANDLE and release all resource."
  (handle #.(lispify "gcry_cipher_hd_t" 'type)))

(cffi:defcfun #.(namify-function-definition "gcry_cipher_ctl")
  #.(lispify "gcry_error_t" 'type)
  "Perform various operations on the cipher object HANDLE."
  (handle #.(lispify "gcry_cipher_hd_t" 'type))
  (cmd :int)
  (buffer :pointer)
  (buflen :size))

(cffi:defcfun #.(namify-function-definition "gcry_cipher_info")
  #.(lispify "gcry_error_t" 'type)
  "Retrieve various information about the cipher object HANDLE."
  (handle #.(lispify "gcry_cipher_hd_t" 'type))
  (what :int)
  (buffer :pointer)
  (nbytes :pointer))

(cffi:defcfun #.(namify-function-definition "gcry_cipher_algo_info")
  #.(lispify "gcry_error_t" 'type)
  "Retrieve various information about the cipher algorithm ALGO."
  (algo :int)
  (what :int)
  (buffer :pointer)
  (nbytes :pointer))

(cffi:defcfun #.(namify-function-definition "gcry_cipher_algo_name")
  :string
  "Map the cipher algorithm whose ID is contained in ALGO to a
string representation of the algorithm name.  For unknown algorithm
IDs this function returns \"?\"."
  (algo :int))

(cffi:defcfun #.(namify-function-definition "gcry_cipher_map_name")
  :int
  "Map the algorithm name NAME to an cipher algorithm ID.
Return 0 if the algorithm name is not known."
  (name :string))

(cffi:defcfun #.(namify-function-definition "gcry_cipher_mode_from_oid")
  :int
  "Given an ASN.1 object identifier in standard IETF dotted decimal
format in STRING, return the encryption mode associated with that
OID or 0 if not known or applicable."
  (string :string))

(cffi:defcfun #.(namify-function-definition "gcry_cipher_encrypt")
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

(cffi:defcfun #.(namify-function-definition "gcry_cipher_decrypt")
  #.(lispify "gcry_error_t" 'type)
  #.(format nil
	    "The counterpart to ~a."
	    '#.(namify-function "gcry_cipher_encrypt"))
  (handle #.(lispify "gcry_cipher_hd_t" 'type))
  (out :pointer)
  (outsize :size)
  (in :pointer)
  (inlen :size))

(cffi:defcfun #.(namify-function-definition "gcry_cipher_setkey")
  #.(lispify "gcry_error_t" 'type)
  "Set KEY of length KEYLEN bytes for the cipher handle HANDLE."
  (handle #.(lispify "gcry_cipher_hd_t" 'type))
  (key :pointer)
  (keylen :size))

(cffi:defcfun #.(namify-function-definition "gcry_cipher_setiv")
  #.(lispify "gcry_error_t" 'type)
  "Set initialization vector IV of length IVLEN for the cipher handle HANDLE."
  (handle #.(lispify "gcry_cipher_hd_t" 'type))
  (iv :pointer)
  (ivlen :size))

(cffi:defcfun #.(namify-function-definition "gcry_cipher_authenticate")
  #.(lispify "gcry_error_t" 'type)
  "Provide additional authentication data for AEAD modes/ciphers."
  (handle #.(lispify "gcry_cipher_hd_t" 'type))
  (abuf :pointer)
  (abuflen :size))

(cffi:defcfun #.(namify-function-definition "gcry_cipher_gettag")
  #.(lispify "gcry_error_t" 'type)
  "Get authentication tag for AEAD modes/ciphers."
  (handle #.(lispify "gcry_cipher_hd_t" 'type))
  (outtag :pointer)
  (taglen :size))

(cffi:defcfun #.(namify-function-definition "gcry_cipher_checktag")
  #.(lispify "gcry_error_t" 'type)
  "Check authentication tag for AEAD modes/ciphers."
  (handle #.(lispify "gcry_cipher_hd_t" 'type))
  (intag :pointer)
  (taglen :size))

(defun #.(namify-function "gcry_cipher_reset") (handle)
  "Reset the handle to the state after open."
  (#.(namify-function "gcry_cipher_ctl")
     handle
     +gcryctl-reset+
     (cffi:null-pointer)
     0))

(defun #.(namify-function "gcry_cipher_sync") (handle)
  "Perform the OpenPGP sync operation if this is enabled 
for the cipher handle HANDLE."
  (#.(namify-function "gcry_cipher_ctl")
     handle
     #.(lispify "GCRYCTL_CFB_SYNC" 'enumvalue)
     (cffi:null-pointer)
     0))

(defun #.(namify-function "gcry_cipher_cts") (handle on)
  "Enable or disable CTS in future calls to gcry_encrypt(). CBC mode only."
  (#.(namify-function "gcry_cipher_ctl")
     handle
     #.(lispify "GCRYCTL_SET_CBC_CTS" 'enumvalue)
     (cffi:null-pointer)
     on))

(defun #.(namify-function "gcry_cipher_set_sbox") (handle oid)
  (#.(namify-function "gcry_cipher_ctl")
     handle
     #.(lispify "GCRYCTL_SET_SBOX" 'enumvalue)
     oid
     0))

(defun #.(namify-function "gcry_cipher_final") (a)
  "Indicate to the encrypt and decrypt functions that the
next call provides the final data.  Only used with some modes."
  (#.(lispify "gcry_cipher_ctl" 'funcation)
     a
     #.(lispify "GCRYCTL_FINALIZE" 'enumvalue)
     (cffi:null-pointer)
     0))

(cffi:defcfun #.(namify-function-definition "gcry_cipher_setctr")
  #.(lispify "gcry_error_t" 'type)
  "Set counter for CTR mode.  (CTR,CTRLEN) must denote a buffer of
block size length, or (NULL,0) to set the CTR to the all-zero block."
  (handle #.(lispify "gcry_cipher_hd_t" 'type))
  (ctr :pointer)
  (ctrlen :size))

(cffi:defcfun #.(namify-function-definition "gcry_cipher_get_algo_keylen")
  :size
  "Retrieve the key length in bytes used with algorithm ALGO."
  (algo :int))

(cffi:defcfun #.(namify-function-definition "gcry_cipher_get_algo_blklen")
  :size
  "Retrieve the block length in bytes used with algorithm ALGO."
  (algo :int))

(defun #.(namify-function "gcry_cipher_test_algo") (algo)
  "Return 0 if the algorithm ALGO is available for use."
  (#.(namify-function "gcry_cipher_algo_info")
     algo
     #.(lispify "GCRYCTL_TEST_ALGO" 'enumvalue)
     (cffi:null-pointer)
     (cffi:null-pointer)))
