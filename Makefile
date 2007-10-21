.PHONY: doc log

doc: posix1e.txt posix1e.html

build/lib.linux-x86_64-2.4/posix1e.so: acl.c
	./setup.py build

posix1e.txt: build/lib.linux-x86_64-2.4/posix1e.so
	PYTHONPATH=build/lib.linux-x86_64-2.4 pydoc posix1e > posix1e.txt

posix1e.html: build/lib.linux-x86_64-2.4/posix1e.so
	PYTHONPATH=build/lib.linux-x86_64-2.4 pydoc -w posix1e
