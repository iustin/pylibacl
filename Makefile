.PHONY: doc log

doc: posix1e.txt posix1e.html
log:
	rm -f ChangeLog
	rcs2log -u 'iusty	Iustin Pop	iusty@k1024.org' > ChangeLog

build/lib.linux-i686-2.2/posix1e.so: acl.c
	./setup.py build

posix1e.txt: build/lib.linux-i686-2.2/posix1e.so
	PYTHONPATH=build/lib.linux-i686-2.2 pydoc posix1e > posix1e.txt

posix1e.html: build/lib.linux-i686-2.2/posix1e.so
	PYTHONPATH=build/lib.linux-i686-2.2 pydoc -w posix1e
