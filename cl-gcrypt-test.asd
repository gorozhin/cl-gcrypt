(in-package :cl-user)
(uiop:define-package cl-gcrypt-test-asd
  (:use #:cl#:asdf #:uiop))
(in-package :cl-gcrypt-test-asd)

(defsystem cl-gcrypt-test
  :version "0.0.1"
  :author "Mikhail Gorozhin <m.gorozhin at gmail.com>"
  :license "LGPLv2.1"
  :depends-on (#:cffi #:cl-gcrypt #:fiveam)
  :description "Common Lisp bindings for libgcrypt test suite"
  :components((:module "t"
	       :components
	       ((:file "test"))))
  :perform (test-op (o c)
		    (format t "~a~%" (symbol-call :fiveam '#:run!
				 (intern* 'cl-gcrypt-suite '#:cl-gcrypt-test)))))
