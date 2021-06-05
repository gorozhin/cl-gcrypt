(in-package :cl-gcrypt)

;;;; control
;;

(defenum
  (#.(lispify "GCRYCTL_FINALIZE" 'enumvalue) 5)
  (#.(lispify "GCRYCTL_TEST_ALGO" 'enumvalue) 8)
  (#.(lispify "GCRYCTL_IS_SECURE" 'enumvalue) 9)
  (#.(lispify "GCRYCTL_GET_ASNOID" 'enumvalue) 10))

;;;; MD module
;; types and structs
(cffi:defcstruct #.(lispify "gcry_md_handle" 'type)
  (ctx :pointer)
  (bufpos :int)
  (bufsize :int)
  (buf :char :count 1))
(cffi:defctype #.(lispify "gcry_md_hd_t" 'type) :pointer)
(cffi:defctype #.(lispify "gcry_error_t" 'type) :uint)
(cffi:defcstruct #.(lispify "gcry_buffer_t" 'type)
  (size :size)
  (off :size)
  (len :size)
  (buf :pointer))

;; algos enum
(defenum
  #.(lispify "GCRY_MD_NONE" 'enumvalue)
  #.(lispify "GCRY_MD_MD5" 'enumvalue)
  #.(lispify "GCRY_MD_SHA1" 'enumvalue)
  #.(lispify "GCRY_MD_RMD160" 'enumvalue)
  (#.(lispify "GCRY_MD_MD2" 'enumvalue) 5)
  #.(lispify "GCRY_MD_TIGER" 'enumvalue)
  #.(lispify "GCRY_MD_HAVAL" 'enumvalue)
  #.(lispify "GCRY_MD_SHA256" 'enumvalue)
  #.(lispify "GCRY_MD_SHA384" 'enumvalue)
  #.(lispify "GCRY_MD_SHA512" 'enumvalue)
  #.(lispify "GCRY_MD_SHA224" 'enumvalue)
  (#.(lispify "GCRY_MD_MD4" 'enumvalue) 301)
  #.(lispify "GCRY_MD_CRC32" 'enumvalue)
  #.(lispify "GCRY_MD_CRC32_RFC1510" 'enumvalue)
  #.(lispify "GCRY_MD_CRC24_RFC2440" 'enumvalue)
  #.(lispify "GCRY_MD_WHIRLPOOL" 'enumvalue)
  #.(lispify "GCRY_MD_TIGER1" 'enumvalue)
  #.(lispify "GCRY_MD_TIGER2" 'enumvalue)
  #.(lispify "GCRY_MD_GOSTR3411_94" 'enumvalue)
  #.(lispify "GCRY_MD_STRIBOG256" 'enumvalue)
  #.(lispify "GCRY_MD_STRIBOG512" 'enumvalue)
  #.(lispify "GCRY_MD_GOSTR3411_CP" 'enumvalue)
  #.(lispify "GCRY_MD_SHA3_224" 'enumvalue)
  #.(lispify "GCRY_MD_SHA3_256" 'enumvalue)
  #.(lispify "GCRY_MD_SHA3_384" 'enumvalue)
  #.(lispify "GCRY_MD_SHA3_512" 'enumvalue)
  #.(lispify "GCRY_MD_SHAKE128" 'enumvalue)
  #.(lispify "GCRY_MD_SHAKE256" 'enumvalue)
  #.(lispify "GCRY_MD_BLAKE2B_512" 'enumvalue)
  #.(lispify "GCRY_MD_BLAKE2B_384" 'enumvalue)
  #.(lispify "GCRY_MD_BLAKE2B_256" 'enumvalue)
  #.(lispify "GCRY_MD_BLAKE2B_160" 'enumvalue)
  #.(lispify "GCRY_MD_BLAKE2S_256" 'enumvalue)
  #.(lispify "GCRY_MD_BLAKE2S_224" 'enumvalue)
  #.(lispify "GCRY_MD_BLAKE2S_160" 'enumvalue)
  #.(lispify "GCRY_MD_BLAKE2S_128" 'enumvalue))

(defenum
  (#.(lispify "GCRY_MD_FLAG_SECURE" 'enumvalue) 1)
  #.(lispify "GCRY_MD_FLAG_HMAC" 'enumvalue)
  (#.(lispify "GCRY_MD_FLAG_BUGEMU1" 'enumvalue) #x0100))

(cffi:defcfun ("gcry_md_open" #.(lispify "gcry_md_open" 'function))
    #.(lispify "gcry_error_t" 'type)
  #.(format nil
	    "Create a message digest object for algorithm ALGO.
Create a message digest object for algorithm ALGO.
FLAGS may be given as an bitwise OR of the ~a values.
ALGO may be given as 0 if the algorithms to be used are later set using ~a"
	    (lispify "gcry_md_flag" 'constant)
	    (lispify "gcry_md_enable" 'function))
  (handle (:pointer #.(lispify "gcry_error_t" 'type)))
  (algo :int)
  (flags :uint))

(cffi:defcfun ("gcry_md_close" #.(lispify "gcry_md_close" 'function))
    :void
  "Release the message digest object HANDLE."
  (handle #.(lispify "gcry_md_hd_t" 'type)))

(cffi:defcfun ("gcry_md_enable" #.(lispify "gcry_md_enable" 'function))
    #.(lispify "gcry_error_t" 'type)
  "Add the message digest algorithm ALGO to the digest object HANDLE"
  (handle #.(lispify "gcry_md_hd_t" 'type))
  (algo :int))

(cffi:defcfun ("gcry_md_copy" #.(lispify "gcry_md_copy" 'function))
    #.(lispify "gcry_error_t" 'type)
  "Create a new digest object as an exact copy of the object HD."
  (bhd :pointer #.(lispify "gcry_md_hd_t" 'type))
  (ahd #.(lispify "gcry_md_hd_t" 'type)))

(cffi:defcfun ("gcry_md_reset" #.(lispify "gcry_md_reset" 'function))
    :void
  "Reset the digest object HANDLE to its initial state."
  (handle #.(lispify "gcry_md_hd_t" 'type)))

(cffi:defcfun ("gcry_md_write" #.(lispify "gcry_md_write" 'function))
    :void
  "Pass LENGTH bytes of data in BUFFER 
to the digest object HANDLE so that
it can update the digest values. This is the actual hash function."
  (handle #.(lispify "gcry_md_hd_t" 'type))
  (buffer :pointer)
  (length :size))

(cffi:defcfun ("gcry_md_read" #.(lispify "gcry_md_read" 'function))
    (:pointer :uchar)
  "Read out the final digest from HANDLE return
 the digest value for algorithm ALGO."
  (handle #.(lispify "gcry_md_hd_t" 'type))
  (algo :int))

(cffi:defcfun ("gcry_md_hash_buffer"
	       #.(lispify "gcry_md_hash_buffer" 'function))
    :void
  "Convenience function to 
calculate the hash from the data in BUFFER 
of size LENGTH using the algorithm ALGO
avoiding the creation of a hash object.
The hash is returned in the caller provided buffer
DIGEST which must be large enough to hold the digest 
of the given algorithm."
  (algo :int)
  (digest :pointer)
  (buffer :pointer)
  (length :size))

(cffi:defcfun ("gcry_md_get_algo"
	       #.(lispify "gcry_md_get_algo" 'function))
    :int
  "Retrieve the algorithm used with HANDLE. 
This does not work reliable if more than
 one algorithm is enabled in HANDLE."
  (handle #.(lispify "gcry_md_hd_t" 'type)))

(cffi:defcfun ("gcry_md_get_algo_dlen"
	       #.(lispify "gcry_md_get_algo_dlen" 'function))
    :uint
  "Retrieve the length in bytes of the
 digest yielded by algorithm ALGO."
  (algo :int))

(cffi:defcfun ("gcry_md_is_enabled"
	       #.(lispify "gcry_md_is_enabled" 'function))
    :boolean
  "Return true if the the algorithm ALGO
is enabled in the digest object HANDLE."
  (handle #.(lispify "gcry_md_hd_t" 'type))
  (algo :int))

(cffi:defcfun ("gcry_md_is_secure"
	       #.(lispify "gcry_md_is_secure" 'function))
    :boolean
  "Return true if the digest object HANDLE
 is allocated in \"secure\" memory."
  (handle #.(lispify "gcry_md_hd_t" 'type)))

(cffi:defcfun ("gcry_md_algo_name"
	       #.(lispify "gcry_md_algo_name" 'function))
    :string
  "Map the digest algorithm id ALGO
to a string representation of the algorithm name.
For unknown algorithms this function returns \"?\"."
  (algo :int))

(cffi:defcfun ("gcry_md_map_name"
	       #.(lispify "gcry_md_map_name" 'function))
    :int
  "Map the algorithm NAME to a digest algorithm Id.
Return 0 if the algorithm name is not known."
  (name :string))

(cffi:defcfun ("gcry_md_setkey"
	       #.(lispify "gcry_md_setkey" 'function))
    #.(lispify "gcry_error_t" 'type)
  "For use with the HMAC feature,
the set MAC key to the KEY of KEYLEN bytes."
  (handle #.(lispify "gcry_md_hd_t" 'type))
  (key :pointer)
  (size :size))

(cffi:defcfun ("gcry_md_algo_info" #.(lispify "gcry_md_algo_info" 'function))
    #.(lispify "gcry_error_t" 'type)
  "Retrieve various information about the algorithm ALGO"
  (algo :int)
  (what :int)
  (buffer :pointer)
  (nbytes (:pointer :size)))

(defun #.(lispify "gcry_md_test_algo" 'function)
  (algo)
  "Return 0 if the algorithm A is available for use."
  (#.(lispify "gcry_md_algo_info" 'function)
     algo
     #.(lispify "GCRYCTL_TEST_ALGO" 'enumvalue)
     (cffi:null-pointer)
     (cffi:null-pointer)))

(defun #.(lispify "gcry_md_get_asnoid" 'function)
  (algo buffer nbytes)
  "Return an DER encoded ASN.1 OID for the algorithm A in buffer B. 
N must point to size_t variable with the available size of buffer B.
After return it will receive the actual size of the returned OID"
  (#.(lispify "gcry_md_algo_info" 'function)
     algo
     #.(lispify "GCRYCTL_GET_ASNOID" 'enumvalue)
     buffer
     nbytes))

(cffi:defcfun ("gcry_md_ctl"
	       #.(lispify "gcry_md_ctl" 'function))
    #.(lispify "gcry_error_t" 'type)
  "Perform various operations on the digest object HANDLE"
  (handle #.(lispify "gcry_md_hd_t" 'type))
  (cmd :int)
  (buffer :pointer)
  (buflen :size))

(defun #.(lispify "gcry_md_final" 'function) (handle)
  #.(format nil
	    "Finalize the digest calculation.
 This is not really needed because ~a does this implicitly"
	    (lispify "gcry_md_read" 'function))
  (#.(lispify "gcry_md_ctl" 'function)
     handle
     #.(lispify "GCRYCTL_FINALIZE" 'enumvalue)
     (cffi:null-pointer)
     0))

(defun #.(lispify "gcry_md_putc" 'function) (handle char)
  #.(format nil
	    "Update the hash(s) of HANDLE with the character CHAR.
  This is a buffered version of the ~a function."
	    (lispify "gcry_md_write" 'function))
  (cffi:with-foreign-slots
      ((bufpos bufsize)
       handle
       (:struct #.(lispify "gcry_md_handle" 'type)))
    (when (= bufpos bufsize)
      (#.(lispify "gcry_md_write" 'function) handle (cffi:null-pointer) 0))
    (let ((buf (cffi:foreign-slot-pointer handle '(:struct #.(lispify "gcry_md_handle" 'type)) 'buf)))
      (setf (cffi:mem-aref buf :char bufpos) char)
      (incf bufpos))))

(cffi:defcfun #.(lispify "gcry_md_debug" 'function)
  :void
  "Start or stop debugging for digest handle HANDLE;
i.e. create a file named dbgmd-<n>.<suffix> while hashing.
If SUFFIX is NULL, debugging stops and the file will be closed."
  (handle #.(lispify "gcry_md_hd_t" 'type))
  (suffix :string))

;; gcry_error_t gcry_md_info (gcry_md_hd_t h, int what, void *buffer,size_t *nbytes)
(cffi:defcfun #.(lispify "gcry_md_info" 'function)
  #.(lispify "gcry_error_t" 'type)
  #.(format nil
	    "Deprecated: Use ~a or ~a."
	    (lispify "gcry_md_is_enabled" 'function)
	    (lispify "gcry_md_is_secure" 'function))
  (handle #.(lispify "gcry_md_hd_t" 'type))
  (what :int)
  (buffer :pointer)
  (nbytes :pointer :size))

(cffi:defcfun
    #.(lispify "gcry_md_extract" 'function)
  #.(lispify "gcry_error_t" 'type)
  "Read more output from algorithm ALGO to BUFFER
of size LENGTH from digest object HANDLE.
 Algorithm needs to be 'expendable-output function'"
  (handle #.(lispify "gcry_md_hd_t" 'type))
  (algo :int)
  (buffer :pointer)
  (length :size))

(cffi:defcfun #.(lispify "gcry_md_hash_buffers" 'function)
  #.(lispify "gcry_error_t" 'type)
  "Convenience function to hash multiple buffers."
  (algo :int)
  (flags :uint)
  (digest :pointer)
  (iov :pointer #.(lispify "gcry_buffer_t" 'type))
  (iovcnt :int))
