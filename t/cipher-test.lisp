(in-package #:cl-gcrypt-test)

(def-suite cl-gcrypt-cipher-suite
  :description "Cipher tests")
(in-suite cl-gcrypt-cipher-suite)

(defun pad-right-with-zeros
    (buffer actual-buffer-length desired-length-multiplier)
  (let* ((padding (if (= desired-length-multiplier 1)
		      0
		      (- desired-length-multiplier
			 (mod actual-buffer-length
			      desired-length-multiplier))))    
	 (new-length (+ actual-buffer-length padding)))
    (let ((new-buffer (foreign-alloc :uint8
				    :initial-element 0
				    :count new-length)))
      (foreign-funcall "memcpy"
     		     :pointer new-buffer
     		     :pointer buffer
     		     :int actual-buffer-length
     		     :void)
    (values new-length new-buffer))))

(test simple
  (unless (gcry-check-version "1.8.0")
    (error "Unsupported gcrypt version"))
  (gcry-control +gcryctl-initialization-finished+
		:int 0)
  (let* ((algo +gcry-cipher-aes+)
	 (flags 0)
	 (string "cl-gcrypt")
	 (foreign-string (convert-to-foreign string :string))
	 (foreign-string-length
	   (foreign-funcall "strlen"
			    :string foreign-string
			    :int))
	 (secret-key "super-secret-key")
	 (foreign-secret-key (convert-to-foreign secret-key :string))
	 (foreign-secret-key-length
	   (foreign-funcall "strlen"
			    :string foreign-secret-key
			    :int)))
     (multiple-value-bind (actual-buffer-length actual-buffer)
	(pad-right-with-zeros foreign-string foreign-string-length 16)
      (with-foreign-object (handle-pointer :pointer)
	(gcry-cipher-open handle-pointer algo 1 flags)
	(let ((handle (mem-aref handle-pointer 'cl-gcrypt:gcry-cipher-hd-t)))
	  (gcry-cipher-setkey handle
			      foreign-secret-key
			      foreign-secret-key-length)
	  (let ((out-buffer
		  (foreign-alloc :int
				 :initial-element 0
				 :count actual-buffer-length)))      
	    (gcry-cipher-encrypt
	     handle
	     out-buffer actual-buffer-length
	     actual-buffer actual-buffer-length)
	    (is (string=
		 "e0f222f7d4e62e30c1f011ad91575af6"
		 (foreign-buffer-to-string out-buffer actual-buffer-length)))
	    (let ((decrypt-buffer
		    (foreign-alloc :int
				   :initial-element 0
				   :count actual-buffer-length)))
	      (gcry-cipher-decrypt
	       handle
	       decrypt-buffer actual-buffer-length
	       out-buffer actual-buffer-length)
	      (is (string= (convert-from-foreign decrypt-buffer :string)
			   string))
	      (foreign-free decrypt-buffer))
	    (foreign-free out-buffer))
	  (gcry-cipher-close handle)))
      (foreign-free actual-buffer))
    (foreign-free foreign-string)
    (foreign-free foreign-secret-key)))

(defun test-one-algo (algo expected string secret-key cipher-mode)
  (let* ((block-length (gcry-cipher-get-algo-blklen algo))
	 (key-length (gcry-cipher-get-algo-keylen algo))
	 (flags 0)
	 (foreign-string (convert-to-foreign string :string))
	 (foreign-string-length
	   (foreign-funcall "strlen" :string foreign-string :int))  
	 (foreign-secret-key (convert-to-foreign secret-key :string))
	 (foreign-secret-key-length
	   (foreign-funcall "strlen" :string foreign-secret-key :int)))
    (multiple-value-bind (padded-key-length padded-key)
	(pad-right-with-zeros foreign-secret-key
			      foreign-secret-key-length
			      key-length)
      
      (with-foreign-object (pointer :pointer)
	(gcry-cipher-open pointer algo cipher-mode flags)
	(let ((handle (mem-aref pointer 'gcry-cipher-hd-t)))
	  
	  (gcry-cipher-setkey handle padded-key padded-key-length)
	  (multiple-value-bind (padded-string-length padded-string)
	      (pad-right-with-zeros foreign-string
				    foreign-string-length
				    block-length)  
	    (let ((encrypted-buffer
		    (foreign-alloc :char
				   :initial-element 0
				   :count padded-string-length))
		  (decrypted-buffer
		    (foreign-alloc :char
				   :initial-element 0
				   :count padded-string-length)))
	      (gcry-cipher-encrypt handle
				   encrypted-buffer
				   padded-string-length
				   padded-string
				   padded-string-length)
	      (gcry-cipher-decrypt handle
				   decrypted-buffer
				   padded-string-length
				   encrypted-buffer
				   padded-string-length)
	      (is (string=
		   (foreign-buffer-to-string encrypted-buffer
					     padded-string-length)
		   expected))
	      (is (string=
		   (foreign-buffer-to-string decrypted-buffer
					     foreign-string-length)
		   (foreign-buffer-to-string foreign-string
					     foreign-string-length)))
	      (foreign-free encrypted-buffer)
	      (foreign-free decrypted-buffer))
	    (foreign-free padded-string))
	  (gcry-cipher-close handle)))
      (foreign-free padded-key))
    (foreign-free foreign-string)
    (foreign-free foreign-secret-key)))

(test all
  (unless (gcry-check-version "1.8.0")
    (error "Unsupported gcrypt version"))
  (gcry-control +gcryctl-initialization-finished+
		:int 0)
  (loop for (cipher expected string secret-key cipher-mode)
	  in
	  (list
	   `(,+gcry-cipher-3-des+
	     "9810ddcfda315d83ad2998b8b90c82e5"
	     nil
	     "@U*(Y!@$OFB!HF@*HUS)")
	   `(,+gcry-cipher-aes+ "0b8f6e33e14b0bfe9477fe380702c743")
	   `(,+gcry-cipher-aes-192+ "af7c91211b68d7c7934d0a875ce0e235")
	   `(,+gcry-cipher-aes-256+ "82443d28ac548774f36e6a8cbecf58c8")
	   `(,+gcry-cipher-blowfish+ "cffe62eaf7ac06ccd7a680b72dbaaca9")
	   `(,+gcry-cipher-camellia-128+ "b6cd1bf11434a2030e878a443aff6876")
	   `(,+gcry-cipher-camellia-192+ "f0975f93c073cb361262f59eca58ee5d")
	   `(,+gcry-cipher-camellia-256+ "5281fa4d9b2195274cecd7b0015cfd39")
	   `(,+gcry-cipher-cast-5+ "6faa061299c61b48d8df62c918b516b3")
	   `(,+gcry-cipher-des+
		 "f80231cca24dbf5e65b7c78833ab7cb9"
		 nil
		 "@U*($")
	   `(,+gcry-cipher-gost-28147+ "55d505738ccf30684e02e9caf33424af")
	   `(,+gcry-cipher-rfc-2268-128+ "fc762181eb3b5eb9f85b55e7b1b0a9f1")
	   `(,+gcry-cipher-rfc-2268-40+ "b82a3e849d9ae1f5a437b0596821a8be") 
	   `(,+gcry-cipher-seed+ "75e5ace689f753ed07159605e67bf9e4")
	   `(,+gcry-cipher-serpent-128+ "105720771533c7ee80b25edc398b7fe3")
	   `(,+gcry-cipher-serpent-192+ "d6024543d455e2319473b178a5a98e2c")
	   `(,+gcry-cipher-serpent-256+ "ac1ce037b887e52281c296ab1294163c")
	   `(,+gcry-cipher-twofish+ "bdcff0fdfc623312aee34219b92644e0")
	   `(,+gcry-cipher-twofish-128+ "eca077fd6ab6d03713f3fed003c8248b"))
	do (let ((string (or string "cl-gcrypt"))
		 (secret-key (or secret-key "secret-key"))
		 (cipher-mode (or cipher-mode +gcry-cipher-mode-ecb+)))
	     (test-one-algo cipher
			    expected
			    string
			    secret-key
			    cipher-mode))))

(test name-id-reversable
  (unless (gcry-check-version "1.8.0")
    (error "Unsupported gcrypt version"))
  (gcry-control +gcryctl-initialization-finished+
		:int 0)
  (let* ((algo +gcry-cipher-blowfish+)
	 (non-existent-algo 999999)
	 (name-from-algo (gcry-cipher-algo-name algo))
	 (name-from-non-existent-algo
	   (gcry-cipher-algo-name non-existent-algo)))
    (is (string= name-from-algo "BLOWFISH"))
    (is (= algo (gcry-cipher-map-name name-from-algo)))
    (is (string= name-from-non-existent-algo "?"))
    (is (= 0 (gcry-cipher-map-name name-from-non-existent-algo)))))

(test oid
  (unless (gcry-check-version "1.8.0")
    (error "Unsupported gcrypt version"))
  (gcry-control +gcryctl-initialization-finished+
		:int 0)
  (is (= (gcry-cipher-mode-from-oid "1.2.840.113549.3.7")
	 +gcry-cipher-mode-cbc+)))

(test algo-available
  (unless (gcry-check-version "1.8.0")
    (error "Unsupported gcrypt version"))
  (gcry-control +gcryctl-initialization-finished+
		:int 0)
  (is (= (gcry-cipher-test-algo +gcry-cipher-blowfish+) 0))
  (is (not (= (gcry-cipher-test-algo 1231231) 0))))

(test initialization-vector-reset
  (unless (gcry-check-version "1.8.0")
    (error "Unsupported gcrypt version"))
  (gcry-control +gcryctl-initialization-finished+
		:int 0)
  (let* ((algo +gcry-cipher-aes+)
	 (cipher-mode +gcry-cipher-mode-cfb+)
	 (string "cl-gcrypt")
	 (secret-key "secret-key")
	 (block-length (gcry-cipher-get-algo-blklen algo))
	 (key-length (gcry-cipher-get-algo-keylen algo))
	 (flags 0)
	 (foreign-string (convert-to-foreign string :string))
	 (foreign-string-length
	   (foreign-funcall "strlen" :string foreign-string :int))  
	 (foreign-secret-key (convert-to-foreign secret-key :string))
	 (foreign-secret-key-length
	   (foreign-funcall "strlen" :string foreign-secret-key :int))
	 (iv "initvect")
	 (foreign-iv (convert-to-foreign iv :string))
	 (foreign-iv-length (foreign-funcall "strlen" :string foreign-iv :int)))
    (multiple-value-bind (padded-key-length padded-key)
	(pad-right-with-zeros foreign-secret-key
			      foreign-secret-key-length
			      key-length)
      (with-foreign-object (pointer :pointer)
	(gcry-cipher-open pointer algo cipher-mode flags)
	(let ((handle (mem-aref pointer 'gcry-cipher-hd-t)))
	  (gcry-cipher-setkey handle padded-key padded-key-length)

	  (multiple-value-bind (padded-string-length padded-string)
	      (pad-right-with-zeros foreign-string
				    foreign-string-length
				    block-length)  
	    (let ((encrypted-buffer
		    (foreign-alloc :char
				   :initial-element 0
				   :count padded-string-length))
		  (decrypted-buffer
		    (foreign-alloc :char
				   :initial-element 0
				   :count padded-string-length)))
	      (gcry-cipher-setiv handle foreign-iv foreign-iv-length)
	      (gcry-cipher-encrypt handle
				   encrypted-buffer
				   padded-string-length
				   padded-string
				   padded-string-length)

	      (gcry-cipher-setiv handle foreign-iv foreign-iv-length)
	      (gcry-cipher-decrypt handle
				   decrypted-buffer
				   padded-string-length
				   encrypted-buffer
				   padded-string-length)
	      (is (string=
		   (foreign-buffer-to-string encrypted-buffer
					     padded-string-length)
		   "0db324cf28f28e00d75ff28b073cc6c2"))
	      (is (string=
		   (foreign-buffer-to-string decrypted-buffer
					     foreign-string-length)
		   (foreign-buffer-to-string foreign-string
					     foreign-string-length)))

	      (gcry-cipher-setiv handle foreign-iv foreign-iv-length)
	      (gcry-cipher-reset handle)
	      (gcry-cipher-encrypt handle
				   encrypted-buffer
				   padded-string-length
				   padded-string
				   padded-string-length)
	      
	      (gcry-cipher-setiv handle foreign-iv foreign-iv-length)
	      (gcry-cipher-reset handle)
	      (gcry-cipher-decrypt handle
				   decrypted-buffer
				   padded-string-length
				   encrypted-buffer
				   padded-string-length)
	      (is (string=
		   (foreign-buffer-to-string encrypted-buffer
					     padded-string-length)
		   "bd6f9922a73efb851b3fc835ec05a9bf"))
	      (is (string=
		   (foreign-buffer-to-string decrypted-buffer
					     foreign-string-length)
		   (foreign-buffer-to-string foreign-string
					     foreign-string-length)))
	      (foreign-free encrypted-buffer)
	      (foreign-free decrypted-buffer))
	    (foreign-free padded-string))
	  (gcry-cipher-close handle)))
      (foreign-free padded-key))
    (foreign-free foreign-string)
    (foreign-free foreign-secret-key)
    (foreign-free foreign-iv)))

(test get-tag
  (unless (gcry-check-version "1.8.0")
    (error "Unsupported gcrypt version"))
  (gcry-control +gcryctl-initialization-finished+
		:int 0)
  (let* ((algo +gcry-cipher-chacha-20+)
	 (cipher-mode +gcry-cipher-mode-poly-1305+)
	 (string "cl-gcrypt")
	 (secret-key "secret-key")
	 (block-length (gcry-cipher-get-algo-blklen algo))
	 (key-length (gcry-cipher-get-algo-keylen algo))
	 (flags 0)
	 (foreign-string (convert-to-foreign string :string))
	 (foreign-string-length
	   (foreign-funcall "strlen" :string foreign-string :int))  
	 (foreign-secret-key (convert-to-foreign secret-key :string))
	 (foreign-secret-key-length
	   (foreign-funcall "strlen" :string foreign-secret-key :int))
	 (tag "3d8cce949681bd185b3d35f8950930f5"))

    (multiple-value-bind (padded-key-length padded-key)
	(pad-right-with-zeros foreign-secret-key
			      foreign-secret-key-length
			      key-length)
      (multiple-value-bind (padded-string-length padded-string)
	  (pad-right-with-zeros foreign-string
				foreign-string-length
				block-length)
	(with-foreign-object (pointer :pointer)
	  (gcry-cipher-open pointer algo cipher-mode flags)

	  (let ((handle (mem-aref pointer 'gcry-cipher-hd-t)))
	    (gcry-cipher-setkey handle padded-key padded-key-length)
	    (let ((encrypted-buffer
		    (foreign-alloc :char
				   :initial-element 0
				   :count padded-string-length))
		  (decrypted-buffer
		    (foreign-alloc :char
				   :initial-element 0
				   :count padded-string-length)))
	      (gcry-cipher-encrypt handle
				   encrypted-buffer
				   padded-string-length
				   padded-string
				   padded-string-length)
	      
	      (let* ((tag-length 16)
		     (tag-buffer (foreign-alloc :uint8
						:initial-element 0
						:count tag-length)))
		(multiple-value-bind (foreign-tag foreign-tag-length)
		    (string-to-foreign-buffer
		     tag)
		  (gcry-cipher-gettag handle tag-buffer tag-length)
		  
		  (is (string=
		       (foreign-buffer-to-string tag-buffer
						 tag-length)
		       tag))
		  (is (= (gcry-cipher-checktag handle
					       foreign-tag
					       foreign-tag-length)
			 0))
		  (foreign-free foreign-tag))) 
	      (foreign-free encrypted-buffer)
	      (foreign-free decrypted-buffer))
	    (gcry-cipher-close handle)))
	(foreign-free padded-string))
      (foreign-free padded-key))
    (foreign-free foreign-string)
    (foreign-free foreign-secret-key)))

(test authenticate
  (unless (gcry-check-version "1.8.0")
    (error "Unsupported gcrypt version"))
  (gcry-control +gcryctl-initialization-finished+
		:int 0)
  (let* ((algo +gcry-cipher-chacha-20+)
	 (cipher-mode +gcry-cipher-mode-poly-1305+)
	 (string "cl-gcrypt")
	 (secret-key "secret-key")
	 (block-length (gcry-cipher-get-algo-blklen algo))
	 (key-length (gcry-cipher-get-algo-keylen algo))
	 (flags 0)
	 (foreign-string (convert-to-foreign string :string))
	 (foreign-string-length
	   (foreign-funcall "strlen" :string foreign-string :int))  
	 (foreign-secret-key (convert-to-foreign secret-key :string))
	 (foreign-secret-key-length
	   (foreign-funcall "strlen" :string foreign-secret-key :int))
	 (tag "fbb7f3393f47eec221040f1510665732")
	 (additional-info "cl-gcrypt-additional-mesage")
	 (foreign-additional-info
	   (convert-to-foreign additional-info
			       :string))
	 (foreign-additional-info-length
	   (foreign-funcall "strlen"
			    :string foreign-additional-info
			    :int)))

    (multiple-value-bind (padded-key-length padded-key)
	(pad-right-with-zeros foreign-secret-key
			      foreign-secret-key-length
			      key-length)
      (multiple-value-bind (padded-string-length padded-string)
	  (pad-right-with-zeros foreign-string
				foreign-string-length
				block-length)
	(with-foreign-object (pointer :pointer)
	  (gcry-cipher-open pointer algo cipher-mode flags)

	  (let ((handle (mem-aref pointer 'gcry-cipher-hd-t)))
	    (gcry-cipher-setkey handle padded-key padded-key-length)
	    (let ((encrypted-buffer
		    (foreign-alloc :char
				   :initial-element 0
				   :count padded-string-length))
		  (decrypted-buffer
		    (foreign-alloc :char
				   :initial-element 0
				   :count padded-string-length)))

	      (gcry-cipher-authenticate handle
					foreign-additional-info
					foreign-additional-info-length)
	      (gcry-cipher-encrypt handle
				   encrypted-buffer
				   padded-string-length
				   padded-string
				   padded-string-length)

	      (let* ((foreign-tag-size (foreign-alloc :size))
		     (tag-length-definition
		       (gcry-cipher-info handle
					 +gcryctl-get-taglen+
					 (null-pointer)
					 foreign-tag-size))
		     (tag-length (mem-aref foreign-tag-size :size))
		     (tag-buffer (foreign-alloc :uint8
						:initial-element 0
						:count tag-length)))
		(declare (ignore tag-length-definition))

		(foreign-free foreign-tag-size)
		(multiple-value-bind (foreign-tag foreign-tag-length)
		    (string-to-foreign-buffer tag)
		  (gcry-cipher-gettag handle tag-buffer tag-length)
		  
		  (is (string=
		       (foreign-buffer-to-string tag-buffer
						 tag-length)
		       tag))
		  (is (= (gcry-cipher-checktag handle
					       foreign-tag
					       foreign-tag-length)
			 0))

		  (gcry-cipher-reset handle)
		  (gcry-cipher-authenticate handle
					foreign-additional-info
					foreign-additional-info-length)
		  (gcry-cipher-decrypt handle
				       decrypted-buffer
				       padded-string-length
				       encrypted-buffer
				       padded-string-length)

		  (is (= (gcry-cipher-checktag handle
					       foreign-tag
					       foreign-tag-length)
			 0))
		  (foreign-free foreign-tag))) 
	      (foreign-free encrypted-buffer)
	      (foreign-free decrypted-buffer))
	    (gcry-cipher-close handle)))
	(foreign-free padded-string))
      (foreign-free padded-key))
    (foreign-free foreign-string)
    (foreign-free foreign-secret-key)
    (foreign-free foreign-additional-info)))
