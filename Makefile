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
	for ver in 2.4 2.5 2.6; do \
	  if type python$$ver >/dev/null; then \
	    python$$ver ./setup.py test; \
          fi; \
	done
