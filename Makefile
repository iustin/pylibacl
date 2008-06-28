.PHONY: doc test

all: doc test

posix1e.so: acl.c
	./setup.py build_ext --inplace

doc: posix1e.so
	epydoc -q -o html --name pylibacl \
		--url http://pylibacl.sourceforge.net/ \
		--show-frames \
		--docformat epytext \
		--no-sourcecode \
		posix1e

test:
	python2.4 ./setup.py test
	python2.5 ./setup.py test
