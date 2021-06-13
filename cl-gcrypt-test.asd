(in-package :cl-user)
(uiop:define-package cl-gcrypt-test-asd
    (:use #:cl #:asdf #:uiop))
(in-package :cl-gcrypt-test-asd)

(defun run-tests ()
  (let ((suites
	  (list (intern* 'cl-gcrypt-cipher-suite '#:cl-gcrypt-test)
		(intern* 'cl-gcrypt-md-suite '#:cl-gcrypt-test))))
    (when (not (reduce
		#'(lambda (x y) (and x y))
		(loop for suite in suites
		      collecting (symbol-call
				  :fiveam '#:run! suite))
		:initial-value t))
      (and (uiop:getenvp "CL_GCRYPT_EXIT_ON_FAIL")
	   (uiop:quit 123)))))

(defsystem cl-gcrypt-test
  :version "0.0.1"
  :author "Mikhail Gorozhin <m.gorozhin at gmail.com>"
  :license "LGPLv2.1"
  :depends-on (#:cl-gcrypt #:cffi #:fiveam #:alexandria #:babel)
  :description "Common Lisp bindings for libgcrypt test suite"
  :components((:module "t"
	       :components
	       ((:file "cl-gcrypt-test")
		(:file "md" :depends-on ("cl-gcrypt-test"))
		(:file "cipher-test" :depends-on ("cl-gcrypt-test")))))
  :perform (test-op (o c)
		    (run-tests)))



