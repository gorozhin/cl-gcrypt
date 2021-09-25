(in-package #:cl-gcrypt-test)

(def-suite cl-gcrypt-sexp-suite
  :description "Symbolic expression tests")
(in-suite cl-gcrypt-sexp-suite)

(let ((was-executed nil))
  (cffi:defcallback simple-free :void ((data :pointer))
    (setf was-executed t)
    (cffi:foreign-free data))

  (defun callback-executed-p ()
    (prog1 was-executed (setf was-executed nil))))

(test create-with-new
  (unless (gcry-check-version "1.8.0")
    (error "Unsupported gcrypt version"))
  (gcry-control +gcryctl-initialization-finished+
		:int 0)
  (let* ((buffer "(a 
 (b 
  (c)
  )
 )
")
	 (foreign-buffer
	   (convert-to-foreign buffer :string))
	 (foreign-buffer-length (foreign-funcall "strlen"
	  					 :string foreign-buffer
	  					 :int))
	 (mode +gcrysexp-fmt-advanced+))
    (with-foreign-object (sexp-pointer :pointer)
      (gcry-sexp-new sexp-pointer
		     foreign-buffer
		     foreign-buffer-length
		     0)
      (let* ((sexp (mem-aref sexp-pointer 'gcry-sexp-t))
	     (sprintf-buffer-length
	       (gcry-sexp-sprint sexp
				 mode
				 (null-pointer)
				 0))
	     (sprintf-buffer
	       (foreign-alloc :uint8
			      :initial-element 0
			      :count sprintf-buffer-length)))
	(gcry-sexp-sprint sexp
			  mode
			  sprintf-buffer
			  sprintf-buffer-length)
	
	(is (string= buffer (convert-from-foreign sprintf-buffer :string)))
	(gcry-sexp-release sexp)))
    (foreign-free foreign-buffer)))

(test create-with-callback
  (unless (gcry-check-version "1.8.0")
    (error "Unsupported gcrypt version"))
  (gcry-control +gcryctl-initialization-finished+
		:int 0)
  (let* ((buffer "(a 
 (b 
  (c)
  )
 )
")
	 (foreign-buffer
	   (convert-to-foreign buffer :string))
	 (foreign-buffer-length (foreign-funcall "strlen"
	  					 :string foreign-buffer
	  					 :int))
	 (mode +gcrysexp-fmt-advanced+))
    (with-foreign-object (sexp-pointer :pointer)
      (gcry-sexp-create sexp-pointer
			foreign-buffer
			foreign-buffer-length
			0
			(cffi:callback simple-free))
      (let* ((sexp (mem-aref sexp-pointer 'gcry-sexp-t))
	     (sprintf-buffer-length
	       (gcry-sexp-sprint sexp
				 mode
				 (null-pointer)
				 0))
	     (sprintf-buffer
	       (foreign-alloc :uint8
			      :initial-element 0
			      :count sprintf-buffer-length)))
	(gcry-sexp-sprint sexp
			  mode
			  sprintf-buffer
			  sprintf-buffer-length)
	
	(is (string= buffer (convert-from-foreign sprintf-buffer :string)))
	(gcry-sexp-release sexp)))
    (foreign-free foreign-buffer))
  (is (callback-executed-p)))

(test create-with-sscan
  (unless (gcry-check-version "1.8.0")
    (error "Unsupported gcrypt version"))
  (gcry-control +gcryctl-initialization-finished+
		:int 0)
  (let* ((buffer "(a 
 (b c)
 )
")
	 (foreign-buffer
	   (convert-to-foreign buffer :string))
	 (foreign-buffer-length (foreign-funcall "strlen"
	  					 :string foreign-buffer
	  					 :int))
	 (mode +gcrysexp-fmt-advanced+)
	 (error-position (cffi:foreign-alloc :uint)))
    (with-foreign-objects ((sexp-pointer :pointer))
      (gcry-sexp-sscan sexp-pointer
		       error-position
		       foreign-buffer
		       foreign-buffer-length)
      (let* ((sexp (mem-aref sexp-pointer 'gcry-sexp-t))
	     (sprintf-buffer-length
	       (gcry-sexp-sprint sexp
				 mode
				 (null-pointer)
				 0))
	     (sprintf-buffer
	       (foreign-alloc :uint8
			      :initial-element 0
			      :count sprintf-buffer-length)))
	(gcry-sexp-sprint sexp
			  mode
			  sprintf-buffer
			  sprintf-buffer-length)
	
	(is (string= buffer (convert-from-foreign sprintf-buffer :string)))
	(gcry-sexp-release sexp)))
    (foreign-free foreign-buffer)
    (foreign-free error-position)))


(test create-with-build
  (unless (gcry-check-version "1.8.0")
    (error "Unsupported gcrypt version"))
  (gcry-control +gcryctl-initialization-finished+
		:int 0)
  (let* ((buffer "(a 
 (%s %s c)
 )
")
	 (expected-string "(a 
 (asdf qwer c)
 )
")
	 (foreign-buffer
	   (convert-to-foreign buffer :string))
	 (mode +gcrysexp-fmt-advanced+)
	 (error-position (cffi:foreign-alloc :uint)))
    (with-foreign-objects ((sexp-pointer :pointer))
      (gcry-sexp-build sexp-pointer
		       error-position
		       foreign-buffer
		       :string "asdf"
		       :string "qwer")
      (let* ((sexp (mem-aref sexp-pointer 'gcry-sexp-t))
	     (sprintf-buffer-length
	       (gcry-sexp-sprint sexp
				 mode
				 (null-pointer)
				 0))
	     (sprintf-buffer
	       (foreign-alloc :uint8
			      :initial-element 0
			      :count sprintf-buffer-length)))
	(gcry-sexp-sprint sexp
			  mode
			  sprintf-buffer
			  sprintf-buffer-length)
	
	(is (string=
	     expected-string
	     (convert-from-foreign sprintf-buffer :string)))
	(gcry-sexp-release sexp)))
    (foreign-free foreign-buffer)
    (foreign-free error-position)))


(test create-with-build-array
  (unless (gcry-check-version "1.8.0")
    (error "Unsupported gcrypt version"))
  (gcry-control +gcryctl-initialization-finished+
		:int 0)
  (let* ((buffer "(a 
 (%s %s c)
 )
")
	 (expected-string "(a 
 (asdf qwer c)
 )
")
	 (foreign-buffer
	   (convert-to-foreign buffer :string))
	 (mode +gcrysexp-fmt-advanced+)
	 (error-position (cffi:foreign-alloc :uint))
	 (array-parameters (cffi:foreign-alloc :pointer :count 2))
	 (foreign-string-1 (convert-to-foreign "asdf" :string))
	 (foreign-string-2 (convert-to-foreign "qwer" :string)))
    (with-foreign-objects
	((sexp-pointer :pointer)
	 (string-1 :pointer)
	 (string-2 :pointer))
      (setf (mem-aref string-1 :pointer) foreign-string-1)
      (setf (mem-aref string-2 :pointer) foreign-string-2)

      (setf (mem-aref array-parameters :pointer 0) string-1)
      (setf (mem-aref array-parameters :pointer 1) string-2)

      (gcry-sexp-build-array sexp-pointer
       			     error-position
       			     foreign-buffer
       			     array-parameters)
      (let* ((sexp (mem-aref sexp-pointer 'gcry-sexp-t))
       	     (sprintf-buffer-length
       	       (gcry-sexp-sprint sexp
       				 mode
       				 (null-pointer)
       				 0))
       	     (sprintf-buffer
       	       (foreign-alloc :uint8
       			      :initial-element 0
       			      :count sprintf-buffer-length)))
       	(gcry-sexp-sprint sexp
       	 		  mode
       	 		  sprintf-buffer
       	 		  sprintf-buffer-length)
       	(is (string=
       	     expected-string
       	     (convert-from-foreign sprintf-buffer :string)))
       	(gcry-sexp-release sexp)))
    (foreign-free foreign-buffer)
    (foreign-free error-position)
    (foreign-free foreign-string-1)
    (foreign-free foreign-string-2)
    (foreign-free array-parameters)))


(test create-canon-len
  (unless (gcry-check-version "1.8.0")
    (error "Unsupported gcrypt version"))
  (gcry-control +gcryctl-initialization-finished+
		:int 0)
  (let* ((buffer "(4:qwer(4:asdf))")
	 (foreign-buffer
	   (convert-to-foreign buffer :string))
	 (foreign-buffer-length (foreign-funcall "strlen"
	  					 :string foreign-buffer
	  					 :int))
	 (error-position (cffi:foreign-alloc :uint))
	 (gcry-error (cffi:foreign-alloc 'gcry-error-t)))

    (is (=
	 foreign-buffer-length
	 (gcry-sexp-canon-len foreign-buffer
			      foreign-buffer-length
			      error-position
			      gcry-error)))
    (foreign-free foreign-buffer)
    (foreign-free error-position)))

(test find-token
  (unless (gcry-check-version "1.8.0")
    (error "Unsupported gcrypt version"))
  (gcry-control +gcryctl-initialization-finished+
		:int 0)
  (let* ((buffer "(a 
 (%s %s c)
 )
")
	 (expected-string "(asdf qwer c)
")
	 (token "asdf")
	 (token-buffer (convert-to-foreign token :string))
	 (token-buffer-length (foreign-funcall "strlen"
					       :string token-buffer
					       :int))
	 (foreign-buffer
	   (convert-to-foreign buffer :string))
	 (mode +gcrysexp-fmt-advanced+)
	 (error-position (cffi:foreign-alloc :uint)))
    (with-foreign-objects ((sexp-pointer :pointer))
      (gcry-sexp-build sexp-pointer
		       error-position
		       foreign-buffer
		       :string token
		       :string "qwer")
      (let* (
	     

	     (sexp (mem-aref sexp-pointer 'gcry-sexp-t))
	     (token-list (gcry-sexp-find-token sexp token-buffer token-buffer-length))
	     (sprintf-buffer-length
	       (gcry-sexp-sprint token-list
				 mode
				 (null-pointer)
				 0))
	     (sprintf-buffer
	       (foreign-alloc :uint8
			      :initial-element 0
			      :count sprintf-buffer-length)))
	(gcry-sexp-sprint token-list
			  mode
			  sprintf-buffer
			  sprintf-buffer-length)
	
	(is (string=
	     expected-string
	     (convert-from-foreign sprintf-buffer :string)))
	(gcry-sexp-release sexp)))
    (foreign-free foreign-buffer)
    (foreign-free error-position)))


(test length
  (unless (gcry-check-version "1.8.0")
    (error "Unsupported gcrypt version"))
  (gcry-control +gcryctl-initialization-finished+
		:int 0)
  (let* ((buffer "(a (%s %s c) (%s %s))")
	 (foreign-buffer
	   (convert-to-foreign buffer :string))
	 (error-position (cffi:foreign-alloc :uint)))
    (with-foreign-objects ((sexp-pointer :pointer))
      (gcry-sexp-build sexp-pointer
		       error-position
		       foreign-buffer
		       :string "asdf"
		       :string "qwer"
		       :string "1234"
		       :string "4321")
      (let* ((sexp (mem-aref sexp-pointer 'gcry-sexp-t))
	     (length (gcry-sexp-length sexp)))
	(is (= length 3))
	(gcry-sexp-release sexp)))
    (foreign-free foreign-buffer)
    (foreign-free error-position)))


(test nth
  (unless (gcry-check-version "1.8.0")
    (error "Unsupported gcrypt version"))
  (gcry-control +gcryctl-initialization-finished+
		:int 0)
  (let* ((buffer "(a (%s %s c) (%s %s))")
	 (expected-string "(asdf qwer c)
")
	 (foreign-buffer
	   (convert-to-foreign buffer :string))
	 (mode +gcrysexp-fmt-advanced+)
	 (error-position (cffi:foreign-alloc :uint)))
    (with-foreign-objects ((sexp-pointer :pointer))
      (gcry-sexp-build sexp-pointer
		       error-position
		       foreign-buffer
		       :string "asdf"
		       :string "qwer"
		       :string "1234"
		       :string "4321")
      (let* ((sexp (mem-aref sexp-pointer 'gcry-sexp-t))
	     (nth (gcry-sexp-nth sexp 1))
	     (sprintf-buffer-length
	       (gcry-sexp-sprint nth
				 mode
				 (null-pointer)
				 0))
	     (sprintf-buffer
	       (foreign-alloc :uint8
			      :initial-element 0
			      :count sprintf-buffer-length)))
	(gcry-sexp-sprint nth
			  mode
			  sprintf-buffer
			  sprintf-buffer-length)
	(is (string= expected-string
		     (convert-from-foreign sprintf-buffer
					   :string)))	
	(gcry-sexp-release sexp)
	(gcry-sexp-release nth)
	(foreign-free sprintf-buffer)))
    (foreign-free foreign-buffer)
    (foreign-free error-position)))

(test car
  (unless (gcry-check-version "1.8.0")
    (error "Unsupported gcrypt version"))
  (gcry-control +gcryctl-initialization-finished+
		:int 0)
  (let* ((buffer "(a (%s %s c) (%s %s))")
	 (expected-string "(a)
")
	 (foreign-buffer
	   (convert-to-foreign buffer :string))
	 (mode +gcrysexp-fmt-advanced+)
	 (error-position (cffi:foreign-alloc :uint)))
    (with-foreign-objects ((sexp-pointer :pointer))
      (gcry-sexp-build sexp-pointer
		       error-position
		       foreign-buffer
		       :string "asdf"
		       :string "qwer"
		       :string "1234"
		       :string "4321")
      (let* ((sexp (mem-aref sexp-pointer 'gcry-sexp-t))
	     (car (gcry-sexp-car sexp))
	     (sprintf-buffer-length
	       (gcry-sexp-sprint car
				 mode
				 (null-pointer)
				 0))
	     (sprintf-buffer
	       (foreign-alloc :uint8
			      :initial-element 0
			      :count sprintf-buffer-length)))
	(gcry-sexp-sprint car
			  mode
			  sprintf-buffer
			  sprintf-buffer-length)
	(is (string= expected-string
		     (convert-from-foreign sprintf-buffer
					   :string)))	
	(gcry-sexp-release sexp)
	(gcry-sexp-release car)
	(foreign-free sprintf-buffer)))
    (foreign-free foreign-buffer)
    (foreign-free error-position)))


(test car
  (unless (gcry-check-version "1.8.0")
    (error "Unsupported gcrypt version"))
  (gcry-control +gcryctl-initialization-finished+
		:int 0)
  (let* ((buffer "(a (%s %s c) (%s %s))")
	 (expected-string "(
 (asdf qwer c)
 )
")
	 (foreign-buffer
	   (convert-to-foreign buffer :string))
	 (mode +gcrysexp-fmt-advanced+)
	 (error-position (cffi:foreign-alloc :uint)))
    (with-foreign-objects ((sexp-pointer :pointer))
      (gcry-sexp-build sexp-pointer
		       error-position
		       foreign-buffer
		       :string "asdf"
		       :string "qwer"
		       :string "1234"
		       :string "4321")
      (let* ((sexp (mem-aref sexp-pointer 'gcry-sexp-t))
	     (cdr (gcry-sexp-cdr sexp))
	     (sprintf-buffer-length
	       (gcry-sexp-sprint cdr
				 mode
				 (null-pointer)
				 0))
	     (sprintf-buffer
	       (foreign-alloc :uint8
			      :initial-element 0
			      :count sprintf-buffer-length)))
	(gcry-sexp-sprint cdr
			  mode
			  sprintf-buffer
			  sprintf-buffer-length)
	(is (string= expected-string
		     (convert-from-foreign sprintf-buffer
					   :string)))	
	(gcry-sexp-release sexp)
	(gcry-sexp-release cdr)
	(foreign-free sprintf-buffer)))
    (foreign-free foreign-buffer)
    (foreign-free error-position)))

(test cadr
  (unless (gcry-check-version "1.8.0")
    (error "Unsupported gcrypt version"))
  (gcry-control +gcryctl-initialization-finished+
		:int 0)
  (let* ((buffer "(a (%s %s c) (%s %s))")
	 (expected-string "(asdf qwer c)
")
	 (foreign-buffer
	   (convert-to-foreign buffer :string))
	 (mode +gcrysexp-fmt-advanced+)
	 (error-position (cffi:foreign-alloc :uint)))
    (with-foreign-objects ((sexp-pointer :pointer))
      (gcry-sexp-build sexp-pointer
		       error-position
		       foreign-buffer
		       :string "asdf"
		       :string "qwer"
		       :string "1234"
		       :string "4321")
      (let* ((sexp (mem-aref sexp-pointer 'gcry-sexp-t))
	     (cadr (gcry-sexp-cadr sexp))
	     (sprintf-buffer-length
	       (gcry-sexp-sprint cadr
				 mode
				 (null-pointer)
				 0))
	     (sprintf-buffer
	       (foreign-alloc :uint8
			      :initial-element 0
			      :count sprintf-buffer-length)))
	(gcry-sexp-sprint cadr
			  mode
			  sprintf-buffer
			  sprintf-buffer-length)
	(is (string= expected-string
		     (convert-from-foreign sprintf-buffer
					   :string)))	
	(gcry-sexp-release sexp)
	(gcry-sexp-release cadr)
	(foreign-free sprintf-buffer)))
    (foreign-free foreign-buffer)
    (foreign-free error-position)))

(test nth-data
  (unless (gcry-check-version "1.8.0")
    (error "Unsupported gcrypt version"))
  (gcry-control +gcryctl-initialization-finished+
		:int 0)
  (let* ((buffer "(a %s %s c %s %s)")
	 (expected-string "qwer")
	 (foreign-buffer
	   (convert-to-foreign buffer :string))
	 (error-position (cffi:foreign-alloc :uint))
	 (data-length (cffi:foreign-alloc :uint)))
    (with-foreign-objects ((sexp-pointer :pointer))
      (gcry-sexp-build sexp-pointer
		       error-position
		       foreign-buffer
		       :string "asdf"
		       :string "qwer"
		       :string "1234"
		       :string "4321")
      (let* ((sexp (mem-aref sexp-pointer 'gcry-sexp-t))
	     (nth-data (gcry-sexp-nth-data sexp 2 data-length)))
	(is (string= expected-string
		     (cffi:foreign-string-to-lisp nth-data
						  :count (mem-aref data-length
								   :uint))))
	(gcry-sexp-release sexp)))
    (foreign-free foreign-buffer)
    (foreign-free error-position)
    (foreign-free data-length)))

(test nth-buffer
  (unless (gcry-check-version "1.8.0")
    (error "Unsupported gcrypt version"))
  (gcry-control +gcryctl-initialization-finished+
		:int 0)
  (let* ((buffer "(a %s %s c %s %s)")
	 (expected-string "qwer")
	 (foreign-buffer
	   (convert-to-foreign buffer :string))	
	 (error-position (cffi:foreign-alloc :uint))
	 (data-length (cffi:foreign-alloc :uint)))
    (with-foreign-objects ((sexp-pointer :pointer))
      (gcry-sexp-build sexp-pointer
		       error-position
		       foreign-buffer
		       :string "asdf"
		       :string "qwer"
		       :string "1234"
		       :string "4321")
      (let* ((sexp (mem-aref sexp-pointer 'gcry-sexp-t))
	     (nth-data (gcry-sexp-nth-buffer sexp 2 data-length)))
	(is (string= expected-string
		     (cffi:foreign-string-to-lisp nth-data
						  :count (mem-aref data-length
								   :uint))))
	(gcry-sexp-release sexp)))
    (foreign-free foreign-buffer)
    (foreign-free error-position)
    (foreign-free data-length)))

(test nth-mpi
  (unless (gcry-check-version "1.8.0")
    (error "Unsupported gcrypt version"))
  (gcry-control +gcryctl-initialization-finished+
		:int 0)
  (let* ((mpi-hex-representation "12de0a")
	 (buffer (format nil "(a %s #~a# c %s %s)" mpi-hex-representation))
	 (foreign-buffer
	   (convert-to-foreign buffer :string))	 
	 (error-position (cffi:foreign-alloc :uint))
	 (written (cffi:foreign-alloc :uint))
	 (mpi-buffer-length 1000)
	 (mpi-buffer (cffi:foreign-alloc :uint :count mpi-buffer-length)))
    (with-foreign-objects ((sexp-pointer :pointer))
      (gcry-sexp-build sexp-pointer
		       error-position
		       foreign-buffer
		       :string "asdf"
		       :string "1234"
		       :string "4321")
      (let* ((sexp (mem-aref sexp-pointer 'gcry-sexp-t))
	     (nth-data (gcry-sexp-nth-mpi sexp 2 1)))
	(gcry-mpi-print +gcrympi-fmt-std+
			mpi-buffer
			mpi-buffer-length
			written
			nth-data)
	(is (string= (foreign-buffer-to-string mpi-buffer
					       (mem-aref written :uint))
		     mpi-hex-representation))
	(gcry-sexp-release sexp)))
    (foreign-free foreign-buffer)
    (foreign-free error-position)
    (foreign-free written)
    (foreign-free mpi-buffer)))



(test nth-extract
  (unless (gcry-check-version "1.8.0")
    (error "Unsupported gcrypt version"))
  (gcry-control +gcryctl-initialization-finished+
		:int 0)
  (let* ((mpi-1-hex-representation "12de0a")
	 (mpi-2-hex-representation "00cafebabe")
	 (mpi-3-hex-representation "18")
	 (buffer
	   (format nil
		   "(a (long (path (to (a #~a#) (b #~a#) (c #~a#)))))"
		   mpi-1-hex-representation
		   mpi-2-hex-representation
		   mpi-3-hex-representation))
	 (foreign-buffer
	   (convert-to-foreign buffer :string))	 
	 (error-position (cffi:foreign-alloc :uint))
	 (written (cffi:foreign-alloc :uint))
	 (path "a!long!path!to")
	 (param-list "abc")
	 (mpi-buffer-length 1000)
	 (mpi-buffer (cffi:foreign-alloc :uint :count mpi-buffer-length)))
    (with-foreign-objects
	((sexp-pointer :pointer)
	 (mpi-1-pointer :pointer)
	 (mpi-2-pointer :pointer)
	 (mpi-3-pointer :pointer))
      (gcry-sexp-build sexp-pointer
		       error-position
		       foreign-buffer)
      (let ((sexp (mem-aref sexp-pointer 'gcry-sexp-t)))
	(gcry-sexp-extract-param sexp
				 path
				 param-list
				 mpi-1-pointer
				 mpi-2-pointer
				 mpi-3-pointer)
	(let* ((mpi-1 (mem-aref mpi-1-pointer 'gcry-sexp-t))
	       (mpi-2 (mem-aref mpi-2-pointer 'gcry-sexp-t))
	       (mpi-3 (mem-aref mpi-3-pointer 'gcry-sexp-t)))	  
	  (gcry-mpi-print +gcrympi-fmt-std+
	   		  mpi-buffer
	   		  mpi-buffer-length
	   		  written
	   		  mpi-1)
	  (is (string= (foreign-buffer-to-string mpi-buffer
						 (mem-aref written :uint))
		       mpi-1-hex-representation))
	  
	  (gcry-mpi-print +gcrympi-fmt-std+
	   		  mpi-buffer
	   		  mpi-buffer-length
	   		  written
	   		  mpi-2)
	  (is (string= (foreign-buffer-to-string mpi-buffer
						 (mem-aref written :uint))
		       mpi-2-hex-representation))
	  (gcry-mpi-print +gcrympi-fmt-std+
	   		  mpi-buffer
	   		  mpi-buffer-length
	   		  written
	   		  mpi-3)
	  (is (string= (foreign-buffer-to-string mpi-buffer
						 (mem-aref written :uint))
		       mpi-3-hex-representation))
	  (gcry-mpi-release mpi-1)
	  (gcry-mpi-release mpi-2)
	  (gcry-mpi-release mpi-3))))
    (foreign-free foreign-buffer)
    (foreign-free error-position)
    (foreign-free written)
    (foreign-free mpi-buffer)))
