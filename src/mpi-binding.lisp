(in-package #:cl-gcrypt)

(cffi:defctype #.(lispify "gcry_mpi_t" 'type) :pointer)

(defenum
    (#.(lispify "GCRYMPI_FMT_NONE" 'enumvalue) 0)
    (#.(lispify "GCRYMPI_FMT_STD" 'enumvalue) 1)
  (#.(lispify "GCRYMPI_FMT_PGP" 'enumvalue) 2)
  (#.(lispify "GCRYMPI_FMT_SSH" 'enumvalue) 3)
  (#.(lispify "GCRYMPI_FMT_HEX" 'enumvalue) 4)
  (#.(lispify "GCRYMPI_FMT_USG" 'enumvalue) 5)
  (#.(lispify "GCRYMPI_FMT_OPAQUE" 'enumvalue) 8))

(cffi:defcfun #.(namify-function-definition "gcry_mpi_print")
  #.(lispify "gcry_error_t" 'type)
  "Convert the big integer A into the external representation 
described by FORMAT and store it in the provided BUFFER which has 
been allocated by the user with a size of BUFLEN bytes.  NWRITTEN 
receives the actual length of the external representation unless it 
has been passed as NULL."
  (format :int)
  (buffer :pointer)
  (buflen :uint)
  (nwritten :pointer)
  (a #.(lispify "gcry_mpi_t" 'type)))

(cffi:defcfun #.(namify-function-definition "gcry_mpi_release")
  :void
  "Release the number A and free all associated resources."
  (a #.(lispify "gcry_mpi_t" 'type)))
