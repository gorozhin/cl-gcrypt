(in-package #:cl-user)
(defpackage cl-gcrypt-asd (:use #:cl #:asdf))
(in-package #:cl-gcrypt-asd)

(defsystem cl-gcrypt
  :version "0.0.1"
  :author "Mikhail Gorozhin <m.gorozhin at gmail.com>"
  :license "LGPLv2.1"
  :depends-on (#:cffi)
  :components ((:module "src"
		:components
		((:file "md-binding" :depends-on ("cl-gcrypt" "helper"))
		 (:file "md-export" :depends-on ("md-binding" "helper"))
		 (:file "cipher-binding" :depends-on ("cl-gcrypt" "helper"))
		 (:file "cipher-export" :depends-on ("cipher-binding" "helper"))
		 (:file "mpi-binding" :depends-on ("cl-gcrypt" "helper"))
		 (:file "mpi-export" :depends-on ("mpi-binding" "helper"))
		 (:file "sexp-binding" :depends-on ("mpi-binding"
						    "cl-gcrypt"
						    "helper"))
		 (:file "sexp-export" :depends-on ("sexp-binding" "helper"))
		 (:file "cl-gcrypt" :depends-on ("helper"))
		 (:file "helper"))))
  :description "Common Lisp bindings for libgcrypt")
