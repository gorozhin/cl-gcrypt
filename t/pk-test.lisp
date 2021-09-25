(in-package #:cl-gcrypt-test)

(def-suite cl-gcrypt-pk-suite
  :description "Assymetric cypto tests")
(in-suite cl-gcrypt-pk-suite)

(defun free-batch (&rest pointers)
  (loop for pointer in pointers do (foreign-free pointer)))

(defun sexp-free-batch (&rest pointers)
  (loop for pointer in pointers do (gcry-sexp-release pointer)))

(test encrypt-decrypt
  (unless (gcry-check-version "1.8.0")
    (error "Unsupported gcrypt version"))
  (gcry-control +gcryctl-initialization-finished+
		:int 0)

  (let* ((raw-data "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Cras convallis egestas metus non dictum.")
	 (data-format "(data (value %s))") 
	 (foreign-data (convert-to-foreign data-format :string))

	 (wrong-data "SOME WRONG DATA")
	 (foreign-wrong-data (convert-to-foreign wrong-data
						 :string))

	 (keys-request "(genkey (rsa (nbits 4:2048)))")
	 (foreign-keys-request
	   (convert-to-foreign keys-request :string))

	 (public-key-token "public-key")
	 (foreign-public-key-token (convert-to-foreign public-key-token
						       :string))
	 (foreign-public-key-token-length
	   (foreign-funcall "strlen"
	  		    :string foreign-public-key-token
	  		    :int))

	 (private-key-token "private-key")
	 (foreign-private-key-token (convert-to-foreign private-key-token
							:string))
	 (foreign-private-key-token-length
	   (foreign-funcall "strlen"
	  		    :string foreign-private-key-token
	  		    :int))

	 (error-position (cffi:foreign-alloc :uint :initial-element 0)))
    (with-foreign-objects
	((keys-request-pointer :pointer)
	 (keys-pointer :pointer)
	 (data-pointer :pointer)
	 (encrypted-pointer :pointer)
	 (decrypted-pointer :pointer)
	 (signed-pointer :pointer))

      (gcry-sexp-build data-pointer
		       error-position
		       foreign-data
		       :string raw-data)
      
      (gcry-sexp-build keys-request-pointer
		       error-position
		       foreign-keys-request)
      
      (let ((keys-request (mem-aref keys-request-pointer 'gcry-sexp-t)))
	(gcry-pk-genkey keys-pointer keys-request)
	
	(let* ((keys (mem-aref keys-pointer 'gcry-sexp-t))
	       (data (mem-aref data-pointer 'gcry-sexp-t))
	       
	       (public-key
		 (gcry-sexp-find-token keys
				       foreign-public-key-token
				       foreign-public-key-token-length))
	       (private-key
		 (gcry-sexp-find-token keys
				       foreign-private-key-token
				       foreign-private-key-token-length)))
	  (gcry-pk-sign signed-pointer data private-key)
	  (is (= 0 (gcry-pk-testkey private-key)))
	  (is (= 2048 (gcry-pk-get-nbits private-key)))
	  
	  (gcry-pk-encrypt encrypted-pointer data public-key)
	  (let ((encrypted (mem-aref encrypted-pointer 'gcry-sexp-t))
		(signed (mem-aref signed-pointer 'gcry-sexp-t)))
	    (is (= (gcry-pk-verify signed data public-key) 0))

	    (gcry-pk-decrypt decrypted-pointer encrypted private-key)

	    (let* ((decrypted (mem-aref decrypted-pointer 'gcry-sexp-t))
		   (decrypted-string (gcry-sexp-nth-string decrypted 0)))
	      (is (string= decrypted-string raw-data))
	      (sexp-free-batch decrypted))
	    (sexp-free-batch encrypted signed))
	  
	  (sexp-free-batch keys data public-key private-key))
	(sexp-free-batch keys-request)))
    (free-batch foreign-data
		foreign-keys-request
		foreign-public-key-token
		foreign-private-key-token
		error-position
		foreign-wrong-data)))

(test map-name
  (unless (gcry-check-version "1.8.0")
    (error "Unsupported gcrypt version"))
  (gcry-control +gcryctl-initialization-finished+
		:int 0)
  (let ((cases `(("DSA" ,+gcry-pk-dsa+)
		 ("RSA" ,+gcry-pk-rsa+))))
    (loop for (name algo) in cases
	  do (is (= algo (gcry-pk-map-name name)))
	     (is (string= (gcry-pk-algo-name algo) name)))))

(test is-available
  (unless (gcry-check-version "1.8.0")
    (error "Unsupported gcrypt version"))
  (gcry-control +gcryctl-initialization-finished+
		:int 0)
  (let ((cases (list +gcry-pk-dsa+ +gcry-pk-rsa+))
	(non-existent-algo 9999))
    (loop for algo in cases
	  do (is (= 0 (gcry-pk-test-algo algo))))
    (is (/= 0 (gcry-pk-test-algo non-existent-algo)))))

(test keygrip
  (unless (gcry-check-version "1.8.0")
    (error "Unsupported gcrypt version"))
  (gcry-control +gcryctl-initialization-finished+
		:int 0)
  (let* ((public-key-request "(public-key 
 (rsa 
  (n #00EA3769A24D6FD33BA26858E6BCC7EB949D20A42B5C5746626B71F50EAD98EED75583B1BB58DB5439ED897BBE33DE1461065CBD9ED6309F07526A96539904FA42E811CA645DBE8002FAEF768C3FA2C4161F4FD41C78BC1F44FEEE4B8AB2DBA2CB48D0CF8A525F6979CFFF88859458B50028910C34CAF2AE76CAE0BC8C6C5A00CF7A717502A367319A9203049B41D613B75341153BA2ACDF38EC898515784D494EF8F7E16F5177FB7318A5E986675AB90C440DD78D5A2DEA2BBD8881209E093A34407D76BBFC02B2DB53A1B4E6703A0BFEC411F8EBA80E297C6085560A2F9F84EA0409B74BA613954B8FE71FC1CC3159D35CD3F6810F402EBFF23B57F37013ABE7#)
  (e #010001#)
  )
 )")
	 (foreign-public-key-request (convert-to-foreign public-key-request
							 :string))
	 (sha1 "74b1dff309444be95e7d026f98047b714505dd68")
	 (error-position (foreign-alloc :uint)))
    (with-foreign-object (public-key-pointer :pointer)
      (gcry-sexp-build public-key-pointer
		       error-position
		       foreign-public-key-request)
      (let ((public-key (mem-aref public-key-pointer 'gcry-sexp-t)))
	(string= (foreign-buffer-to-string (gcry-pk-get-keygrip
					    public-key
					    (null-pointer))
					   20)
		 sha1)
	(sexp-free-batch public-key)))
    (free-batch foreign-public-key-request error-position)))

(test get-param
  (unless (gcry-check-version "1.8.0")
    (error "Unsupported gcrypt version"))
  (gcry-control +gcryctl-initialization-finished+
		:int 0)
  (let* ((name "NIST P-224")
	 (sexp (gcry-pk-get-param +gcry-pk-ecc+ name))
	 (expected-mpi "00ffffffffffffffffffffffffffffffff000000000000000000000001")
	 (mpi-buffer-length 1000)
	 (mpi-buffer (cffi:foreign-alloc :uint :count mpi-buffer-length))
	 (written (cffi:foreign-alloc :uint))
	 (nbit (cffi:foreign-alloc :uint)))
    (with-foreign-object (mpi-pointer :pointer)
      (let ((extract-param-error (gcry-sexp-extract-param sexp
							  "public-key!ecc"
							  "p"
							  mpi-pointer)))
        (is (string= (gcry-pk-get-curve sexp 0 nbit) name))
	(is (= extract-param-error 0))
	(when (= extract-param-error 0)
	  (let ((mpi (mem-aref mpi-pointer 'gcry-mpi-t)))
	    (gcry-mpi-print +gcrympi-fmt-std+
			    mpi-buffer
			    mpi-buffer-length
			    written
			    mpi)
	    (is (string= expected-mpi
		    (foreign-buffer-to-string mpi-buffer
					      (mem-aref written :uint))))
	    (gcry-mpi-release mpi)))))
    (sexp-free-batch sexp)
    (free-batch mpi-buffer written nbit)))
