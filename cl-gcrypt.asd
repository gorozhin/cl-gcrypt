(in-package :cl-user)
(defpackage cl-gcrypt-asd (:use :cl :asdf))
(in-package :cl-gcrypt-asd)

(defsystem cl-gcrypt
  :version "0.0.1"
  :author "Mikhail Gorozhin <m.gorozhin at gmail.com>"
  :license "LGPLv2.1"
  :depends-on (:cffi)
  :components ((:module "src"
		:components
		((:file "binding" :depends-on ("cl-gcrypt" "helper"))
		 (:file "export" :depends-on ("binding" "helper"))
		 (:file "cl-gcrypt" :depends-on ("helper"))
		 (:file "helper"))))
  :description "Common Lisp bindings for libgcrypt")