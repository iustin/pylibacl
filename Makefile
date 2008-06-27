.PHONY: doc log test

doc: posix1e.txt posix1e.html

build/lib.linux-x86_64-2.4/posix1e.so: acl.c
	./setup.py build

posix1e.so: acl.c
	./setup.py build_ext --inplace

posix1e.txt: posix1e.so
	pydoc posix1e > posix1e.txt

posix1e.html: posix1e.so
	pydoc -w posix1e

test:
	python2.4 ./setup.py test
	python2.5 ./setup.py test
