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

(cl:defmacro defenum (cl:&rest definitions)
  `(progn ,@(cl:loop
	       for definition in definitions
	       for index = 0 then (cl:1+ index)
	       when (cl:listp definition) do
		 (cl:setf
		  index (cl:second definition)
		  definition (cl:first definition))
	       collecting `(cl:defconstant
			       ,definition
			     ,index))))

(eval-when (:compile-toplevel :load-toplevel)
  (cl:defun lispify (name flag cl:&optional (package cl:*package*))
    (cl:concatenate 'cl:list name)
    (cl:labels ((helper
		    (list last accumulator cl:&aux (c (cl:car list)))
		  (cl:cond ((cl:null list) accumulator)
			   ((cl:upper-case-p c)
			    (helper
			     (cdr list)
			     'upper
			     (cl:case last
			       ((lower digit)
				(cl:list* c #\- accumulator))
			       (cl:t (cl:cons c accumulator)))))
			   ((cl:lower-case-p c)
			    (helper (cdr list)
				    'lower
				    (cl:cons
				     (cl:char-upcase c)
				     accumulator)))
			   ((cl:digit-char-p c)
			    (helper (cdr list)
				    'digit
				    (cl:case last
				      ((lower upper)
				       (cl:list* c #\- accumulator))
				      (cl:t (cl:cons c accumulator)))))
			   ((or (cl:char-equal c #\_)
				(cl:char-equal c #\-))
			    (helper (cdr list)
				    '_
				    (cl:case last
				      (_ accumulator)
				      (cl:t (cl:cons #\- accumulator)))))
			   (cl:t (cl:error "Unsupported symbol ~a" c)))))
      (cl:let ((fix
		 (cl:case flag
		   ((constant enumvalue) "+")
		   (variable "*")
		   (cl:t ""))))
	(cl:intern
	 (cl:concatenate 'string
			 fix
			 (cl:nreverse
			  (helper (cl:concatenate 'list name)
				  cl:nil
				  cl:nil))
			 fix)
	 package))))
  
  (cl:defun namify-function (name) (lispify name 'function))
  (cl:defun namify-function-definition (name)
    (list name (namify-function name))))
