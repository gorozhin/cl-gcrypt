(in-package :cl-user)
(defpackage cl-gcrypt.helper
  (:use :cl)
  (:export
   :lispify
   :enumvalue
   :constant
   :defenum
   :namify-function
   :namify-function-definition))
(in-package :cl-gcrypt.helper)

(defmacro defenum (&rest definitions)
  `(progn ,@(loop
	       for definition in definitions
	       for index = 0 then (1+ index)
	       when (listp definition) do
		 (setf
		  index (second definition)
		  definition (first definition))
	       collecting `(defconstant
			       ,definition
			     ,index))))

(eval-when (:compile-toplevel :load-toplevel)
  (defun lispify (name flag &optional (package *package*))
    (concatenate 'list name)
    (labels ((helper
		    (list last accumulator &aux (c (car list)))
		  (cond ((null list) accumulator)
			   ((upper-case-p c)
			    (helper
			     (cdr list)
			     'upper
			     (case last
			       ((lower digit)
				(list* c #\- accumulator))
			       (t (cons c accumulator)))))
			   ((lower-case-p c)
			    (helper (cdr list)
				    'lower
				    (cons
				     (char-upcase c)
				     accumulator)))
			   ((digit-char-p c)
			    (helper (cdr list)
				    'digit
				    (case last
				      ((lower upper)
				       (list* c #\- accumulator))
				      (t (cons c accumulator)))))
			   ((or (char-equal c #\_)
				(char-equal c #\-))
			    (helper (cdr list)
				    '_
				    (case last
				      (_ accumulator)
				      (t (cons #\- accumulator)))))
			   (t (error "Unsupported symbol ~a" c)))))
      (let ((fix
		 (case flag
		   ((constant enumvalue) "+")
		   (variable "*")
		   (t ""))))
	(intern
	 (concatenate 'string
			 fix
			 (nreverse
			  (helper (concatenate 'list name)
				  nil
				  nil))
			 fix)
	 package))))
  
  (defun namify-function (name) (lispify name 'function))
  (defun namify-function-definition (name)
    (list name (namify-function name))))
