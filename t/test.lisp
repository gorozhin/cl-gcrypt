(in-package #:cl-user)

(uiop:define-package #:cl-gcrypt-test
  (:use #:cl #:cl-gcrypt #:cffi #:fiveam)
  (:export #:cl-gcrypt-test-suite))

(in-package #:cl-gcrypt-test)

(def-suite cl-gcrypt-suite
  :description "Tests")

(in-suite cl-gcrypt-suite)
  
(test test
  (is (= 1 1)))

(test failing-test
  (is (= 1 2)))
