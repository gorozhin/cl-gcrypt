(in-package #:cl-user)
(uiop:define-package #:cl-gcrypt-test
  (:use #:cl #:cl-gcrypt #:cffi #:fiveam #:alexandria #:babel)
  (:export #:cl-gcrypt-cipher-suite
	   #:cl-gcrypt-md-suite))
(in-package #:cl-gcrypt-test)

(defun foreign-buffer-to-string (buffer length)
  (unless (null-pointer-p buffer)
    (let ((stream (make-string-output-stream)))
	(loop for index
   	      below length
   	      do (format stream "~2,'0x"		   
   			 (mem-aref buffer :uchar index)))
	(string-downcase (get-output-stream-string stream)))))

(defun split-by-n (string n)
  (let ((string-length (length string)))
    (loop for i from 0 to string-length by n
	  as j = (subseq string i (min (+ i n) string-length))
	  with list = nil
	  when (/= (length j) 0) do (setf list (cons j list))
	    finally (return (reverse list)))))

(defun string-to-foreign-buffer (string)
  (let* ((n 2)
	 (string-length (length string))
	 (buffer-length (ceiling (/ string-length n)))
	 (buffer (foreign-alloc :uint8
				:initial-element 0
				:count buffer-length)))
    (loop for i in (split-by-n string n)
	  for j below buffer-length
	  do (setf (mem-aref buffer :uint8 j)
		   (parse-integer i :radix 16))
	  finally (return (values buffer buffer-length)))))


