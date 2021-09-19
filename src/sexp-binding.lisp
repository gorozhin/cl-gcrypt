(in-package #:cl-gcrypt)

(cffi:defctype #.(lispify "gcry_sexp_t" 'type) :pointer)

(defenum
  #.(lispify "GCRYSEXP_FMT_DEFAULT" 'enumvalue)
  #.(lispify "GCRYSEXP_FMT_CANON" 'enumvalue)
  #.(lispify "GCRYSEXP_FMT_BASE64" 'enumvalue)
  #.(lispify "GCRYSEXP_FMT_ADVANCED" 'enumvalue))

(cffi:defcfun
    #.(namify-function-definition "gcry_sexp_new")
  #.(lispify "gcry_error_t" 'type)
  "Create an new S-expression object from BUFFER of size LENGTH and 
return it in RETSEXP.  With AUTODETECT set to 0 the data in BUFFER 
is expected to be in canonized format."
  (retsexp :pointer '#.(lispify "gcry_sexp_t" 'type))
  (buffer :pointer)
  (length :uint)
  (autodetect :int))

(cffi:defcfun
    #.(namify-function-definition "gcry_sexp_create")
  #.(lispify "gcry_error_t" 'type)
  #.(format nil
	    "Same as ~a but allows to pass a FREEFNC which has the
effect to transfer ownership of BUFFER to the created object."
	    (namify-function "gcry_sexp_new"))
  (retsexp :pointer '#.(lispify "gcry_sexp_t" 'type))
  (buffer :pointer)
  (length :uint)
  (autodetect :int)
  (freefnc :pointer))

(cffi:defcfun
    #.(namify-function-definition "gcry_sexp_sscan")
  #.(lispify "gcry_error_t" 'type)
  "Scan BUFFER and return a new S-expression object in RETSEXP.
This function expects a printf like string in BUFFER."
  (retsexp :pointer '#.(lispify "gcry_sexp_t" 'type))
  (erroff :pointer)
  (buffer :pointer)
  (length :uint))

(defmacro #.(namify-function "gcry_sexp_build")
  (retsexp erroff format &rest arguments)
  #.(format nil
	    "Same as ~a but expects a string in FORMAT 
and can thus only be used for certain encodings."
	    (namify-function "gcry_sexp_sscan"))
  `(cffi:foreign-funcall "gcry_sexp_build"
			:pointer ,retsexp
			:pointer ,erroff
			:string ,format
			,@arguments
			#.(lispify "gcry_error_t" 'type)))

(cffi:defcfun #.(namify-function-definition "gcry_sexp_build_array")
  #.(lispify "gcry_error_t" 'type)
  #.(format nil
	    "Like ~a, but uses an array instead of
variable function arguments."
	    (namify-function "gcry_sexp_build"))
  (retsexp :pointer)
  (erroff :pointer)
  (format :string)
  (arg-list :pointer))

(cffi:defcfun
    #.(namify-function-definition "gcry_sexp_release")
  :void
  "Release the S-expression object SEXP"
  (sexp #.(lispify "gcry_sexp_t" 'type)))

(cffi:defcfun
    #.(namify-function-definition "gcry_sexp_canon_len")
  :uint
  "Calculate the length of an canonized S-expression in BUFFER and 
check for a valid encoding."
  (buffer :pointer)
  (length :uint)
  (erroff :pointer)
  (errcode :pointer #.(lispify "gcry_error_t" 'type)))

(cffi:defcfun
    #.(namify-function-definition "gcry_sexp_sprint")
  :uint
  "Copies the S-expression object SEXP into BUFFER using the format 
specified in MODE."
  (sexp #.(lispify "gcry_sexp_t" 'type))
  (mode :int)
  (buffer :pointer)
  (maxlength :uint))

(cffi:defcfun
    #.(namify-function-definition "gcry_sexp_dump")
  :void
  "Dumps the S-expression object A in a format suitable for debugging 
to Libgcrypt's logging stream."
  (a #.(lispify "gcry_sexp_t" 'type)))

(cffi:defcfun
    #.(namify-function-definition "gcry_sexp_cons")
  #.(lispify "gcry_sexp_t" 'type)
  (a #.(lispify "gcry_sexp_t" 'type))
  (b #.(lispify "gcry_sexp_t" 'type)))

(cffi:defcfun
    #.(namify-function-definition "gcry_sexp_alist")
  #.(lispify "gcry_sexp_t" 'type)
  (a :pointer #.(lispify "gcry_sexp_t" 'type)))

(defmacro #.(namify-function "gcry_sexp_vlist")
  (a &rest arguments)
  #.(format nil
	    "Same as ~a but expects a string in FORMAT and can thus only be used for certain encodings."
	    (namify-function "gcry_sexp_sscan"))
  `(cffi:foreign-funcall "gcry_sexp_build"
			 :pointer ,a
			 ,@(loop for argument in arguments nconcing `(:pointer ,argument))
			 #.(lispify "gcry_error_t" 'type)))

(cffi:defcfun
    #.(namify-function-definition "gcry_sexp_append")
  #.(lispify "gcry_sexp_t" 'type)
  (a #.(lispify "gcry_sexp_t" 'type))
  (b #.(lispify "gcry_sexp_t" 'type)))

(cffi:defcfun
    #.(namify-function-definition "gcry_sexp_prepend")
  #.(lispify "gcry_sexp_t" 'type)
  (a #.(lispify "gcry_sexp_t" 'type))
  (b #.(lispify "gcry_sexp_t" 'type)))

(cffi:defcfun
    #.(namify-function-definition "gcry_sexp_find_token")
  #.(lispify "gcry_sexp_t" 'type)
  "Scan the S-expression for a sublist with a type (the car of the list) 
matching the string TOKEN.  If TOKLEN is not 0, the token is 
assumed to be raw memory of this length.  The function returns a 
newly allocated S-expression consisting of the found sublist or 
`NULL' when not found."
  (list #.(lispify "gcry_sexp_t" 'type))
  (tok :pointer)
  (toklen :uint))

(cffi:defcfun
    #.(namify-function-definition "gcry_sexp_length")
  :int
  "Return the length of the LIST.  For a valid S-expression this 
should be at least 1."
  (list #.(lispify "gcry_sexp_t" 'type)))

(cffi:defcfun
    #.(namify-function-definition "gcry_sexp_nth")
  #.(lispify "gcry_sexp_t" 'type)
  "Create and return a new S-expression from the element with index 
NUMBER in LIST.  Note that the first element has the index 0. If 
there is no such element, `NULL' is returned."
  (list #.(lispify "gcry_sexp_t" 'type))
  (number :int))

(cffi:defcfun
    #.(namify-function-definition "gcry_sexp_car")
  #.(lispify "gcry_sexp_t" 'type)
  "Create and return a new S-expression from the first element in 
LIST; this called the \"type\" and should always exist and be a 
string. `NULL' is returned in case of a problem."
  (list #.(lispify "gcry_sexp_t" 'type)))

(cffi:defcfun
    #.(namify-function-definition "gcry_sexp_cdr")
  #.(lispify "gcry_sexp_t" 'type)
  "Create and return a new list form all elements except for the first 
one.  Note, that this function may return an invalid S-expression 
because it is not guaranteed, that the type exists and is a string. 
However, for parsing a complex S-expression it might be useful for 
intermediate lists.  Returns `NULL' on error."
  (list #.(lispify "gcry_sexp_t" 'type)))

(cffi:defcfun
    #.(namify-function-definition "gcry_sexp_cadr")
  #.(lispify "gcry_sexp_t" 'type)
  (list #.(lispify "gcry_sexp_t" 'type)))

(cffi:defcfun
    #.(namify-function-definition "gcry_sexp_nth_data")
  :pointer
  "This function is used to get data from a LIST.  A pointer to the 
actual data with index NUMBER is returned and the length of this 
data will be stored to DATALEN.  If there is no data at the given 
index or the index represents another list, `NULL' is returned. 
*Note:* The returned pointer is valid as long as LIST is not 
modified or released."
  (list #.(lispify "gcry_sexp_t" 'type))
  (number :int)
  (datalen :pointer))

(cffi:defcfun
    #.(namify-function-definition "gcry_sexp_nth_buffer")
  :pointer
  "This function is used to get data from a LIST.  A malloced buffer to 
the data with index NUMBER is returned and the length of this 
data will be stored to RLENGTH.  If there is no data at the given 
index or the index represents another list, `NULL' is returned."
  (list #.(lispify "gcry_sexp_t" 'type))
  (number :int)
  (rlength :pointer))

(cffi:defcfun
    #.(namify-function-definition "gcry_sexp_nth_string")
  :string
  "This function is used to get and convert data from a LIST. 
The data is assumed to be a Nul terminated string.  The caller must 
release the returned value using `gcry_free'.  If there is no data 
at the given index, the index represents a list or the value can't 
be converted to a string, `NULL' is returned."
  (list #.(lispify "gcry_sexp_t" 'type))
  (number :int))

(cffi:defcfun
    #.(namify-function-definition "gcry_sexp_nth_mpi")
  #.(lispify "gcry_mpi_t" 'type)
  "This function is used to get and convert data from a LIST. This
   data is assumed to be an MPI stored in the format described by
   MPIFMT and returned as a standard Libgcrypt MPI.  The caller must
   release this returned value using `gcry_mpi_release'.  If there is
   no data at the given index, the index represents a list or the
   value can't be converted to an MPI, `NULL' is returned."
  (list #.(lispify "gcry_sexp_t" 'type))
  (number :int)
  (mpifmt :int))



(defmacro #.(namify-function "gcry_sexp_extract_param")
  (sexp path list &rest arguments)
  "Extract MPIs from an s-expression using a list of parameters.  The 
names of these parameters are given by the string LIST.  Some 
special characters may be given to control the conversion:
 
     + :: Switch to unsigned integer format (default).
     - :: Switch to standard signed format.
     / :: Switch to opaque format.
     & :: Switch to buffer descriptor mode - see below.
     ? :: The previous parameter is optional.
 
In general parameter names are single letters.  To use a string for 
a parameter name, enclose the name in single quotes.
 
Unless in gcry_buffer_t mode for each parameter name a pointer to 
an MPI variable is expected that must be set to NULL prior to 
invoking this function, and finally a NULL is expected.  Example:
 
    _gcry_sexp_extract_param (key, NULL, \"n/x+ed\",
                              &mpi_n, &mpi_x, &mpi_e, NULL)
 
This stores the parameter \"N\" from KEY as an unsigned MPI into 
MPI_N, the parameter \"X\" as an opaque MPI into MPI_X, and the 
parameter \"E\" again as an unsigned MPI into MPI_E.
 
If in buffer descriptor mode a pointer to gcry_buffer_t descriptor 
is expected instead of a pointer to an MPI.  The caller may use two 
different operation modes: If the DATA field of the provided buffer 
descriptor is NULL, the function allocates a new buffer and stores 
it at DATA; the other fields are set accordingly with OFF being 0. 
If DATA is not NULL, the function assumes that DATA, SIZE, and OFF 
describe a buffer where to but the data; on return the LEN field 
receives the number of bytes copied to that buffer; if the buffer 
is too small, the function immediately returns with an error code 
(and LEN set to 0).
 
PATH is an optional string used to locate a token.  The exclamation 
mark separated tokens are used to via gcry_sexp_find_token to find 
a start point inside SEXP.
 
The function returns 0 on success. On error an error code is 
returned, all passed MPIs that might have been allocated up to this 
point are deallocated and set to NULL, and all passed buffers are 
either truncated if the caller supplied the buffer, or deallocated 
if the function allocated the buffer."
  `(cffi:foreign-funcall "gcry_sexp_extract_param"
			 #.(lispify "gcry_sexp_t" 'type) ,sexp
			 :string ,path
			 :string ,list
			 ,@(loop for argument in arguments nconcing `(:pointer ,argument))
			 :pointer (cffi:null-pointer)
			 #.(lispify "gcry_error_t" 'type)))
