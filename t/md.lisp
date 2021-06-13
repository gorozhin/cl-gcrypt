(in-package #:cl-gcrypt-test)

(def-suite cl-gcrypt-md-suite
  :description "Message digest tests")
(in-suite cl-gcrypt-md-suite)

(defun perform-simple-hash-test
    (algo expected &key (string "cl-gcrypt") (flags 0))
  (let* ((foreign-string (convert-to-foreign string :string))
	 (foreign-string-length
	   (foreign-funcall "strlen"
			    :string foreign-string
			    :int))
	 (algo-digest-len (gcry-md-get-algo-dlen algo)))
    (with-foreign-object (handle-pointer :pointer)
      (gcry-md-open handle-pointer algo flags)
      (let ((handle (mem-aref handle-pointer 'gcry-md-hd-t)))
	(gcry-md-write handle
		       foreign-string
		       foreign-string-length)
	(let ((resulting-buffer (gcry-md-read handle algo)))
	  (is (string= (string-downcase expected)
		       (foreign-buffer-to-string
			resulting-buffer
			   algo-digest-len))))
	(gcry-md-close handle)))
    (foreign-free foreign-string)))

(defun perform-buffered-hash-test
    (algo expected &key (string "cl-gcrypt") (flags 0))
  (let* ((foreign-string (convert-to-foreign string :string))
	 (algo-digest-len (gcry-md-get-algo-dlen algo)))
    (with-foreign-object (handle-pointer :pointer)
      (gcry-md-open handle-pointer algo flags)
      (let ((handle (mem-aref handle-pointer 'gcry-md-hd-t)))
	(loop for character across (string-to-octets string)
	      do (gcry-md-putc handle (convert-to-foreign character :char)))
	(let ((resulting-buffer (gcry-md-read handle algo)))
	  (is (string= (string-downcase expected)
		       (foreign-buffer-to-string
			resulting-buffer
			   algo-digest-len))))
	(gcry-md-close handle)))
    (foreign-free foreign-string)))

(defmacro perform-simple-hash-test-cases
    (&rest test-cases)
  `(progn ,@(loop for (algo expected . others) in test-cases
		  collecting
		  `(perform-simple-hash-test ,algo
					     ,expected
					     ,@others))))

(defmacro perform-buffered-hash-test-cases
    (&rest test-cases)
  `(progn ,@(loop for (algo expected . others) in test-cases
		  collecting
		  `(perform-buffered-hash-test ,algo
					       ,expected
					       ,@others))))

(test simple-hash
  (perform-simple-hash-test-cases
   (+gcry-md-md-5+ "828560813092bf2f8eedf55dd99df999")
   (+gcry-md-sha-1+ "db3787abcf47c4783f9f520258f3f5cee4c2ddb4")
   (+gcry-md-rmd-160+
    "7dc54aa4a7106b86cb284c140d99f4513aae0833")
   ;; md-2 is not implemented in libgcrypt, but it is reserved
   (+gcry-md-tiger+
    "02dc0bac07cc64568617d720e180b38dbda3bd3c4f8accb5")
   ;; haval algo is not implemented in libgcrypt, but it is reserved
   (+gcry-md-sha-256+ "c293a87cb0c3b41794b535fd80c2936b8ad29e69fed2e2916a69a0324987a7eb")
   (+gcry-md-sha-384+ "5f5e742ee8df128ba8b642e568a1719c2a45ab6aa8075acde03f13f169a99a34ae32e22f3443621cf07b80b24c576b29")
   (+gcry-md-sha-512+ "4ec89318c959dae76bbd469fdb3a49dbcf317a1350bcc3241ef1527d674fed3336d63ffc1a495cf1d356cb26cae5edd179edf16319c97dbfc79bfd5135f5e715")
   (+gcry-md-sha-224+ "4fd270a8f1004e11a64fe45d4e865b62dbb60d4af793094e604187e3")
   (+gcry-md-md-4+ "9aa45e07068c784ba3f4f7ffcc28d54b")
   (+gcry-md-crc-32+ "83eb8103")
   (+gcry-md-crc-32-rfc-1510+ "65e295ad")
   (+gcry-md-crc-24-rfc-2440+ "2c5ec2")
   (+gcry-md-whirlpool+ "fcc7281ccd60ec9c00fb80d0ae3288aec877e30a81ced91bb6c4cbbdd4297f283ee557709b4d73724f4a80219c3691e1686879f8547604a85c76e412768faf6b")
   (+gcry-md-tiger-1+ "5664cc07ac0bdc028db380e120d71786b5cc8a4f3cbda3bd")
   (+gcry-md-tiger-2+ "352084cc01a42599fbc8f026dcfd83623c4a08862b0b7009")
   (+gcry-md-gostr-3411-94+ "603c880312dd2bcfcb717de191b6550656ff3b17694a529180c4563794d12fa1")
   (+gcry-md-stribog-256+ "15cde75f71eda0452087d26623762b8ac37e02902c20fa9621204e0e6428fbce")
   (+gcry-md-stribog-512+ "177393cbf63b72865f2054205f4b3965e133e5f962addb756c136c07ec7d7b8119c3a7c2c00aaa2ade7a367461c8746cfb3b03087a88eaee3e4d2d781cde953b")
   (+gcry-md-gostr-3411-cp+ "1e1337a2eafb94ad1e15ea5887859ad3bb637c7fae4b7202dcbb49e5723e0edc")
   (+gcry-md-sha-3-224+ "07fb67303c9ea811d7f861659b164add1cdc3425b395c8d16ddc5ca8")
   (+gcry-md-sha-3-256+ "9bf58615b2ad57371ce9bfa42611b614dd2a7174103edc02ceaaf9bc8f1ecdea")
   (+gcry-md-sha-3-384+ "c4f0810a07d206f2e520203c3a14dc3c2b86bd36cb2546d6bbcd918fa7b4f33d58e6df8fa0cd258f105aa6f1db472794")
   (+gcry-md-sha-3-512+ "a53945914a089385c7520ad9ea7476aeea02aae9241855252ee8668e2859d8381a480319b959dadf51ca10d71d25e3fd0f0f10b1c605754d6fa610efa31eae2b")
   (+gcry-md-blake-2-b-512+ "486f5018762362cd9f4fd5c2fc1914e23abe17e2a4f88653de39a45d5a4d437fe57710e5c99b5e74a4d603eb1a3205cdb7388d6d06f6b177b34dafcb2d390f64")
   (+gcry-md-blake-2-b-384+ "24bf3e0d765c1ba896707b1f911df5a14a695a2bf397c6818949d8f857c8ef941ed8f687d5282d59d3ada4f7703907d1")
   (+gcry-md-blake-2-b-256+ "b2144a0d9cc93c9ae4f306c75bb36a66e8cae7ae884d4dd53f3da4949911ce65")
   (+gcry-md-blake-2-b-160+ "3f48945e1f6172fa1bbdaf2931b65ebd2f5758bf")
   (+gcry-md-blake-2-s-256+ "a6d8c508ae9badf542f646e7cbdd9080946a7417314ee1022e72c997b9d21aaf")
   (+gcry-md-blake-2-s-224+ "5f297cf66ac5cad9dc3c81b8922a4c6b79f8fd04a0a402054e9a03cf")
   (+gcry-md-blake-2-s-160+ "6806a27aca24eb897e3608d4744177d3be88990c")
   (+gcry-md-blake-2-s-128+ "1eb752c0295d7a8d9c7a78745c643c73")))

(test simple-hash-secure-memory
  (perform-simple-hash-test-cases
   (+gcry-md-md-5+ "828560813092bf2f8eedf55dd99df999" :flags +gcry-md-flag-secure+)
   (+gcry-md-sha-1+ "db3787abcf47c4783f9f520258f3f5cee4c2ddb4" :flags +gcry-md-flag-secure+)
   (+gcry-md-whirlpool+ "fcc7281ccd60ec9c00fb80d0ae3288aec877e30a81ced91bb6c4cbbdd4297f283ee557709b4d73724f4a80219c3691e1686879f8547604a85c76e412768faf6b" :flags +gcry-md-flag-secure+)))

(test buffered-hash
  (perform-buffered-hash-test-cases
   (+gcry-md-md-5+ "828560813092bf2f8eedf55dd99df999")
   (+gcry-md-sha-1+ "db3787abcf47c4783f9f520258f3f5cee4c2ddb4")
   (+gcry-md-whirlpool+ "fcc7281ccd60ec9c00fb80d0ae3288aec877e30a81ced91bb6c4cbbdd4297f283ee557709b4d73724f4a80219c3691e1686879f8547604a85c76e412768faf6b")))

(test buffered-hash-secure-memory
  (perform-buffered-hash-test-cases
   (+gcry-md-md-5+ "828560813092bf2f8eedf55dd99df999" :flags +gcry-md-flag-secure+)
   (+gcry-md-sha-1+ "db3787abcf47c4783f9f520258f3f5cee4c2ddb4" :flags +gcry-md-flag-secure+)
   (+gcry-md-whirlpool+ "fcc7281ccd60ec9c00fb80d0ae3288aec877e30a81ced91bb6c4cbbdd4297f283ee557709b4d73724f4a80219c3691e1686879f8547604a85c76e412768faf6b" :flags +gcry-md-flag-secure+)))

(test is-enabled-is-secure-test
  (with-foreign-objects ((secure-handle-pointer :pointer)
			 (non-secure-handle-pointer :pointer))
    (gcry-md-open secure-handle-pointer
		  +gcry-md-md-5+
		  +gcry-md-flag-secure+)
    (gcry-md-open non-secure-handle-pointer
		  +gcry-md-md-5+
		  0)
    (let ((secure-handle (mem-aref secure-handle-pointer 'gcry-md-hd-t))
	  (non-secure-handle (mem-aref non-secure-handle-pointer 'gcry-md-hd-t)))
      (is-true (gcry-md-is-secure secure-handle))
      (is-false (gcry-md-is-secure non-secure-handle))
      (is-true (gcry-md-is-enabled secure-handle +gcry-md-md-5+))
      (is-false (gcry-md-is-enabled secure-handle +gcry-md-sha-1+))
      (gcry-md-close secure-handle)
      (gcry-md-close non-secure-handle))))

(test re-enable
  (let* ((string "cl-gcrypt")
	 (flags 0)
	 (algo +gcry-md-none+)
	 (later-enabled-algo +gcry-md-md-5+)
	 (foreign-string (convert-to-foreign string :string))
	 (foreign-string-length
	   (foreign-funcall "strlen"
			    :string foreign-string
			    :int))
	 (algo-digest-len (gcry-md-get-algo-dlen later-enabled-algo)))
    (with-foreign-object (handle-pointer :pointer)
      (gcry-md-open handle-pointer algo flags)
      (let ((handle (mem-aref handle-pointer 'gcry-md-hd-t)))
	(gcry-md-enable handle +gcry-md-md-5+)
	(gcry-md-write handle
		       foreign-string
		       foreign-string-length)
	(let ((resulting-buffer (gcry-md-read handle algo)))
	  (is (string= (string-downcase "828560813092bf2f8eedf55dd99df999")
		       (foreign-buffer-to-string
			resulting-buffer
			algo-digest-len))))
	(gcry-md-close handle)))
      (foreign-free foreign-string)))

(test multiple-enable
  (let* ((string "cl-gcrypt")
	 (flags 0)
	 (algo +gcry-md-md-5+)
	 (second-algo +gcry-md-sha-1+)     
	 (foreign-string (convert-to-foreign string :string))
	 (foreign-string-length
	   (foreign-funcall "strlen"
			    :string foreign-string
			    :int))
	 (algo-digest-len (gcry-md-get-algo-dlen algo))
	 (second-algo-digest-len (gcry-md-get-algo-dlen second-algo)))
    (with-foreign-object (handle-pointer :pointer)
      (gcry-md-open handle-pointer algo flags)
      (let ((handle (mem-aref handle-pointer 'gcry-md-hd-t)))
	(gcry-md-enable handle +gcry-md-sha-1+)
	(is-true (gcry-md-is-enabled handle algo))
	(is-true (gcry-md-is-enabled handle second-algo))
	(gcry-md-write handle foreign-string foreign-string-length)
	(let ((resulting-buffer (gcry-md-read handle algo))
	      (second-resulting-buffer (gcry-md-read handle second-algo)))
	  (is (string= (string-downcase "828560813092bf2f8eedf55dd99df999")
		       (foreign-buffer-to-string
			resulting-buffer
			algo-digest-len)))
	  (is (string= (string-downcase "db3787abcf47c4783f9f520258f3f5cee4c2ddb4")
		       (foreign-buffer-to-string
			second-resulting-buffer
			second-algo-digest-len))))
	(gcry-md-close handle)))))

(test algo-name-back-and-forth
  (let ((algo +gcry-md-md-5+))
    (is (= (gcry-md-map-name (gcry-md-algo-name algo)) algo))))

(test reset
  (let* ((some-other-string "some-other-string")
	 (string "cl-gcrypt")
	 (algo +gcry-md-md-5+)
	 (flags 0)
	 (foreign-string (convert-to-foreign string :string))
	 (foreign-string-length
	   (foreign-funcall "strlen"
			    :string foreign-string
			    :int))
	 (some-other-foreign-string (convert-to-foreign
				     some-other-string
				     :string))
	 (some-other-foreign-string-length
	   (foreign-funcall "strlen"
			    :string some-other-foreign-string
			    :int))
	 (algo-digest-len (gcry-md-get-algo-dlen algo)))
    (with-foreign-object (handle-pointer :pointer)
      (gcry-md-open handle-pointer algo flags)
      (let ((handle (mem-aref handle-pointer 'gcry-md-hd-t)))
	(gcry-md-write handle
		       some-other-foreign-string
		       some-other-foreign-string-length)
	(gcry-md-reset handle)
	(gcry-md-write handle
		       foreign-string
		       foreign-string-length)
	(let ((resulting-buffer (gcry-md-read handle algo)))
	  (is (string= (string-downcase "828560813092bf2f8eedf55dd99df999")
		       (foreign-buffer-to-string
			resulting-buffer
			   algo-digest-len))))
	(gcry-md-close handle)))
    (foreign-free foreign-string)
    (foreign-free some-other-foreign-string)))

(test algo-available
  (is (= 0 (gcry-md-test-algo +gcry-md-md-5+)))
  (is (not (= 0 (gcry-md-test-algo +gcry-md-md-2+))))
  (is (not (= 0 (gcry-md-test-algo 1000)))))

(test hash-buffer
  (let* ((algo +gcry-md-md-5+)
	 (string "cl-gcrypt")
	 (foreign-string (convert-to-foreign string :string))
	 (foreign-string-length
	   (foreign-funcall "strlen"
			    :string foreign-string
			    :int))
	 (algo-length (gcry-md-get-algo-dlen algo))
	 (digest (foreign-alloc :char :initial-element 0 :count algo-length)))
    (gcry-md-hash-buffer algo digest foreign-string foreign-string-length)
    (is (string= (string-downcase "828560813092bf2f8eedf55dd99df999")
	   (foreign-buffer-to-string digest algo-length)))
    (foreign-free foreign-string)
    (foreign-free digest)))

(test get-algo
  (let* ((algo +gcry-md-md-5+)
	 (flags 0))
    (with-foreign-object (handle-pointer :pointer)
      (gcry-md-open handle-pointer algo flags)
      (let ((handle (mem-aref handle-pointer 'gcry-md-hd-t)))
	(is (= +gcry-md-md-5+ (gcry-md-get-algo handle)))
	(is (not (= +gcry-md-sha-1+ (gcry-md-get-algo handle))))
	(gcry-md-close handle)))))

(test test-ctl
  (let* ((string "cl-gcrypt")
	 (algo +gcry-md-md-5+)
	 (flags 0)
	 (foreign-string (convert-to-foreign string :string))
	 (algo-digest-len (gcry-md-get-algo-dlen algo)))
    (with-foreign-object (handle-pointer :pointer)
      (gcry-md-open handle-pointer algo flags)
      (let ((handle (mem-aref handle-pointer 'gcry-md-hd-t)))
	(loop for character across (string-to-octets string)
	      for index from 0
	      if (= index 2) do (gcry-md-final handle)
	      do (gcry-md-putc handle (convert-to-foreign character :char)))
	(let ((resulting-buffer (gcry-md-read handle algo)))
	  (is (string= (string-downcase "161747ec4dc9f55f1760195593742232")
		       (foreign-buffer-to-string
			resulting-buffer
			   algo-digest-len))))
	(gcry-md-close handle)))
    (foreign-free foreign-string)))


(test hash-buffers
  (let* ((algo +gcry-md-md-5+)
	 (str "cl-g")
	 (str1 "crypt")		 
	 (digest-len (cl-gcrypt:gcry-md-get-algo-dlen algo))
	 (digest (foreign-alloc :int8
				:initial-element 0
				:count digest-len))
	  (iov (foreign-alloc '(:struct gcry-buffer-t) :count 2))
	  (foreign-string1 (convert-to-foreign str :string))	
	  (foreign-string2 (convert-to-foreign str1 :string))
	  (len (foreign-funcall "strlen"
				:string foreign-string1
				:int))
	  (len1 (foreign-funcall "strlen"
				:string foreign-string2
				:int)))
      (cffi:with-foreign-objects
       	  ((iov1 '(:struct gcry-buffer-t))
	   (iov2 '(:struct gcry-buffer-t)))

	(setf
	 (foreign-slot-value iov1 '(:struct gcry-buffer-t) 'cl-gcrypt:size)
	 len
	 (foreign-slot-value iov2 '(:struct gcry-buffer-t) 'cl-gcrypt:size)
	 len1
	 (foreign-slot-value iov1 '(:struct gcry-buffer-t) 'cl-gcrypt:off)
	 0
	 (foreign-slot-value iov2 '(:struct gcry-buffer-t) 'cl-gcrypt:off)
	 0
	 (foreign-slot-value iov1 '(:struct gcry-buffer-t) 'cl-gcrypt:len)
	 len
	 (foreign-slot-value iov2 '(:struct gcry-buffer-t) 'cl-gcrypt:len)
	 len1
	 (foreign-slot-value iov1 '(:struct gcry-buffer-t) 'cl-gcrypt:buf)
	 foreign-string1
	 (foreign-slot-value iov2 '(:struct gcry-buffer-t) 'cl-gcrypt:buf)
	 foreign-string2)
	(foreign-funcall
	 "memcpy"
         :pointer (mem-aptr iov '(:struct gcry-buffer-t) 0)
         :pointer iov1
         :int (foreign-type-size '(:struct gcry-buffer-t))
         :void)
	(foreign-funcall
	  "memcpy"
          :pointer (mem-aptr iov '(:struct gcry-buffer-t) 1)
          :pointer iov2
          :int (foreign-type-size '(:struct gcry-buffer-t))
          :void)
	(gcry-md-hash-buffers algo 0 digest iov 2))
    (is (string= "828560813092bf2f8eedf55dd99df999"
		 (foreign-buffer-to-string digest digest-len)))
    (foreign-free iov)
    (foreign-free foreign-string1)
    (foreign-free foreign-string2)
    (foreign-free digest)))

(test get-asnoid
  (let ((buffer (cffi:foreign-alloc :uchar :initial-element 0 :count 100))
	(size (cffi:foreign-alloc :size :initial-element 100)))

    (cl-gcrypt:gcry-md-get-asnoid cl-gcrypt:+gcry-md-md-5+ buffer size)
    (is (string=
	 "3020300c06082a864886f70d020505000410"
	 (foreign-buffer-to-string buffer (mem-aref size :size))))
    (cl-gcrypt:gcry-md-get-asnoid cl-gcrypt:+gcry-md-sha-1+ buffer size)
    (is (string=
	 "3021300906052b0e03021a05000414"
	 (foreign-buffer-to-string buffer (mem-aref size :size))))
    (cffi:foreign-free buffer)
    (cffi:foreign-free size)))

(test copy
  (let* ((string "cl-gcrypt")
	 (flags 0)
	 (algo +gcry-md-md-5+)
	 (foreign-string (convert-to-foreign string :string))
	 (foreign-string-length
	   (foreign-funcall "strlen"
			    :string foreign-string
			    :int))
	 (algo-digest-len (gcry-md-get-algo-dlen algo)))
    (with-foreign-objects ((handle-pointer :pointer)
			  (copied-handle-pointer :pointer))
      (gcry-md-open handle-pointer algo flags)
      (let ((handle (mem-aref handle-pointer 'gcry-md-hd-t)))
	(gcry-md-write handle
		       foreign-string
		       foreign-string-length)
	(gcry-md-copy copied-handle-pointer handle)
	(let* ((copied-handle (mem-aref copied-handle-pointer 'gcry-md-hd-t))
	       (resulting-buffer (gcry-md-read copied-handle algo)))
	  (is (string= (string-downcase "828560813092bf2f8eedf55dd99df999")
		       (foreign-buffer-to-string
			resulting-buffer
			algo-digest-len)))
	  (gcry-md-close copied-handle))
	(gcry-md-close handle)))
    (foreign-free foreign-string)))


(test extended-output-algo
  (let* ((string "cl-gcrypt")
	 (algo +gcry-md-shake-128+)
	 (flags 0)
	 (foreign-string (convert-to-foreign string :string))
	 (foreign-string-length
	   (foreign-funcall "strlen"
			    :string foreign-string
			    :int)))
    (with-foreign-object (handle-pointer :pointer)
      (gcry-md-open handle-pointer algo flags)
      (let ((handle (mem-aref handle-pointer 'gcry-md-hd-t)))
	(gcry-md-write handle
		       foreign-string
		       foreign-string-length)
	(let* ((resulting-buffer-length 5)
	       (resulting-buffer (foreign-alloc :uint8
						:initial-element 0
						:count resulting-buffer-length)))
	  (gcry-md-extract handle
			   algo
			   resulting-buffer
			   resulting-buffer-length)
	  (is (string= (string-downcase "d4a2b45507")
		       (foreign-buffer-to-string
			resulting-buffer
			resulting-buffer-length)))
	  (gcry-md-extract handle
			   algo
			   resulting-buffer
			   resulting-buffer-length)
	  (is (string= (string-downcase "409b42c3b6")
		       (foreign-buffer-to-string
			resulting-buffer
			resulting-buffer-length))))
	(gcry-md-close handle)))
    (foreign-free foreign-string)))

(test hmac
  (let* ((string "cl-gcrypt")
	 (algo +gcry-md-md-5+)
	 (flags +gcry-md-flag-hmac+)
	 (secret-key "secret key")
	 (foreign-string (convert-to-foreign string :string))
	 (foreign-string-length
	   (foreign-funcall "strlen"
			    :string foreign-string
			    :int))	 
	 (foreign-secret-key (convert-to-foreign secret-key :string))
	 (foreign-secret-key-length
	   (foreign-funcall "strlen"
			    :string foreign-secret-key
			    :int))
	 (algo-digest-len (gcry-md-get-algo-dlen algo)))
    (with-foreign-object (handle-pointer :pointer)
      (gcry-md-open handle-pointer algo flags)
      (let ((handle (mem-aref handle-pointer 'gcry-md-hd-t)))
	(gcry-md-setkey handle foreign-secret-key foreign-secret-key-length)
	(gcry-md-write handle
		       foreign-string
		       foreign-string-length)
	(let ((resulting-buffer (gcry-md-read handle algo)))
	  (is (string= (string-downcase "69f2f9498714104a591479daebb17337")
		       (foreign-buffer-to-string
			resulting-buffer
			algo-digest-len))))
	(gcry-md-close handle)))
    (foreign-free foreign-string)
    (foreign-free foreign-secret-key)))

(test is-secure-via-info
  (with-foreign-objects ((secure-handle-pointer :pointer)
			 (non-secure-handle-pointer :pointer))
    (gcry-md-open secure-handle-pointer
		  +gcry-md-md-5+
		  +gcry-md-flag-secure+)
    (gcry-md-open non-secure-handle-pointer
		  +gcry-md-md-5+
		  0)
    (let ((secure-handle (mem-aref secure-handle-pointer 'gcry-md-hd-t))
	  (non-secure-handle (mem-aref non-secure-handle-pointer
				       'gcry-md-hd-t))
	  (buffer (foreign-alloc :int :count 10))
	  (nbytes (foreign-alloc :size)))      
      (gcry-md-info secure-handle +gcryctl-is-secure+ buffer nbytes)
      (is (= 1 (mem-aref nbytes :int)))      
      (gcry-md-info non-secure-handle +gcryctl-is-secure+ buffer nbytes)
      (is (= 0 (mem-aref nbytes :int)))

      (setf (mem-aref buffer :int) +gcry-md-md-5+)
      (setf (mem-aref nbytes :int) 0)

      (foreign-free buffer)
      (foreign-free nbytes)
      (gcry-md-close secure-handle)
      (gcry-md-close non-secure-handle))))
