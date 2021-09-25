(in-package #:cl-gcrypt)

(defenum
  (#.(lispify "GCRY_PK_RSA" 'enumvalue) 1)
  #.(lispify "GCRY_PK_RSA_E" 'enumvalue)
  #.(lispify "GCRY_PK_RSA_S" 'enumvalue)
  (#.(lispify "GCRY_PK_ELG_E" 'enumvalue) 16)
  #.(lispify "GCRY_PK_DSA" 'enumvalue)
  #.(lispify "GCRY_PK_ECC" 'enumvalue)
  (#.(lispify "GCRY_PK_ELG" 'enumvalue) 20)
  (#.(lispify "GCRY_PK_ECDSA" 'enumvalue) 301)
  #.(lispify "GCRY_PK_ECDH" 'enumvalue)
  #.(lispify "GCRY_PK_EDDSA" 'enumvalue))

(defenum
  (#.(lispify "GCRY_PK_USAGE_SIGN" 'enumvalue) 1)
  (#.(lispify "GCRY_PK_USAGE_ENCR" 'enumvalue) 2)
  (#.(lispify "GCRY_PK_USAGE_CERT" 'enumvalue) 4)
  (#.(lispify "GCRY_PK_USAGE_AUTH" 'enumvalue) 8)
  (#.(lispify "GCRY_PK_USAGE_UNKN" 'enumvalue) 128))

(defenum
    (#.(lispify "GCRY_PK_GET_PUBKEY" 'enumvalue) 1)
    #.(lispify "GCRY_PK_GET_SECKEY" 'enumvalue))

(cffi:defcfun #.(namify-function-definition "gcry_pk_encrypt")
  #.(lispify "gcry_error_t" 'type)
  "Encrypt the DATA using the public key PKEY and store the result as 
a newly created S-expression at RESULT."
  (result :pointer #.(lispify "gcry_sexp_t" 'type))
  (data #.(lispify "gcry_sexp_t" 'type))
  (pkey #.(lispify "gcry_sexp_t" 'type)))

(cffi:defcfun #.(namify-function-definition "gcry_pk_decrypt")
  #.(lispify "gcry_error_t" 'type)
  "Decrypt the DATA using the private key SKEY and store the result as 
a newly created S-expression at RESULT."
  (result :pointer #.(lispify "gcry_sexp_t" 'type))
  (data #.(lispify "gcry_sexp_t" 'type))
  (skey #.(lispify "gcry_sexp_t" 'type)))

(cffi:defcfun #.(namify-function-definition "gcry_pk_sign")
  #.(lispify "gcry_error_t" 'type)
  "Sign the DATA using the private key SKEY and store the result as 
a newly created S-expression at RESULT."
  (result :pointer #.(lispify "gcry_sexp_t" 'type))
  (data #.(lispify "gcry_sexp_t" 'type))
  (skey #.(lispify "gcry_sexp_t" 'type)))

(cffi:defcfun #.(namify-function-definition "gcry_pk_verify")
  #.(lispify "gcry_error_t" 'type)
  "Check the signature SIGVAL on DATA using the public key PKEY."
  (sigval #.(lispify "gcry_sexp_t" 'type))
  (data #.(lispify "gcry_sexp_t" 'type))
  (pkey #.(lispify "gcry_sexp_t" 'type)))

(cffi:defcfun #.(namify-function-definition "gcry_pk_testkey")
  #.(lispify "gcry_error_t" 'type)
  "Check that private KEY is sane."
  (key #.(lispify "gcry_sexp_t" 'type)))

(cffi:defcfun #.(namify-function-definition "gcry_pk_genkey")
  #.(lispify "gcry_error_t" 'type)
  "Generate a new key pair according to the parameters given in 
S_PARMS.  The new key pair is returned in as an S-expression in 
R_KEY."
  (r_key :pointer #.(lispify "gcry_sexp_t" 'type))
  (s_parms #.(lispify "gcry_sexp_t" 'type)))

(cffi:defcfun #.(namify-function-definition "gcry_pk_ctl")
  #.(lispify "gcry_error_t" 'type)
  "Catch all function for miscellaneous operations."
  (cmd :int)
  (buffer :pointer)
  (buflen :uint))

(cffi:defcfun #.(namify-function-definition "gcry_pk_algo_info")
  #.(lispify "gcry_error_t" 'type)
  "Retrieve information about the public key algorithm ALGO."
  (algo :int)
  (what :int)
  (buffer :pointer)
  (nbytes :pointer))

(cffi:defcfun #.(namify-function-definition "gcry_pk_algo_name")
  :string
  "Map the public key algorithm whose ID is contained in ALGORITHM to
   a string representation of the algorithm name.  For unknown
   algorithm IDs this functions returns \"?\"."
  (algorithm :int))

(cffi:defcfun #.(namify-function-definition "gcry_pk_map_name")
  :int
  "Map the algorithm NAME to a public key algorithm Id.  Return 0 if 
the algorithm name is not known."
  (name :string))

(cffi:defcfun #.(namify-function-definition "gcry_pk_get_nbits")
  :uint
  "Return what is commonly referred as the key length for the given 
public or private KEY."
  (key #.(lispify "gcry_sexp_t" 'type)))

(cffi:defcfun #.(namify-function-definition "gcry_pk_get_keygrip")
  :pointer
  "Return the so called KEYGRIP which is the SHA-1 hash of the public 
key parameters expressed in a way depending on the algorithm."
  (key #.(lispify "gcry_sexp_t" 'type))
  (array :pointer))

(cffi:defcfun #.(namify-function-definition "gcry_pk_get_curve")
  :string
  "Return the name of the curve matching KEY."
  (key #.(lispify "gcry_sexp_t" 'type))
  (iterator :int)
  (r_nbits :pointer))

(cffi:defcfun #.(namify-function-definition "gcry_pk_get_param")
  #.(lispify "gcry_sexp_t" 'type)
  "Return an S-expression with the parameters of the named ECC curve 
NAME. ALGO must be set to an ECC algorithm."
  (algo :int)
  (name :string))

(defmacro #.(namify-function "gcry_pk_test_algo")
  (a)
  "Return 0 if the public key algorithm A is available for use."
  `(#.(namify-function "gcry_pk_algo_info")
      ,a
      #.(lispify "GCRYCTL_TEST_ALGO" 'enumvalue)
      (cffi:null-pointer)
      (cffi:null-pointer)))

(cffi:defcfun #.(namify-function-definition "gcry_pubkey_get_sexp")
  #.(lispify "gcry_error_t" 'type)
  "Return an S-expression representing the context CTX."
  (sexp :pointer #.(lispify "gcry_sexp_t" 'type))
  (mode :int)
  (ctx #.(lispify "gcry_ctx_t" 'type)))
