(in-package :cl-user)
(uiop:define-package cl-gcrypt-test-asd
    (:use #:cl #:asdf #:uiop))
(in-package :cl-gcrypt-test-asd)

(defun run-tests ()
  (when (not (symbol-call
	      :fiveam '#:run!
	      (intern* 'cl-gcrypt-suite '#:cl-gcrypt-test)))
    (and (uiop:getenvp "CL_GCRYPT_EXIT_ON_FAIL") (uiop:quit 123))))

(defsystem cl-gcrypt-test
  :version "0.0.1"
  :author "Mikhail Gorozhin <m.gorozhin at gmail.com>"
  :license "LGPLv2.1"
  :depends-on (#:cl-gcrypt #:cffi #:fiveam #:alexandria #:babel)
  :description "Common Lisp bindings for libgcrypt test suite"
  :components((:module "t"
	       :components
	       ((:file "test"))))
  :perform (test-op (o c)
		    (run-tests)))



