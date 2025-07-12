PYTHON        = python3
SPHINXOPTS    = -W
SPHINXBUILD   = $(PYTHON) -m sphinx
DOCDIR        = doc
DOCHTML       = $(DOCDIR)/html
DOCTREES      = $(DOCDIR)/doctrees
ALLSPHINXOPTS = -d $(DOCTREES) $(SPHINXOPTS) $(DOCDIR)
VERSION       = 0.7.3
FULLVER       = pylibacl-$(VERSION)
DISTFILE      = $(FULLVER).tar.gz

MODNAME = posix1e.so
DOCFILES = doc/index.rst doc/module.rst doc/news.md doc/readme.md doc/conf.py

all: doc test

$(MODNAME): acl.c
	$(PYTHON) ./setup.py build_ext --inplace

$(DOCHTML)/index.html: $(MODNAME) $(DOCFILES) acl.c
	$(SPHINXBUILD) -b html $(ALLSPHINXOPTS) $(DOCHTML)
	touch $@

doc: $(DOCHTML)/index.html

dist:
	fakeroot $(PYTHON) ./setup.py sdist

distcheck: dist
	set -e; \
	TDIR=$$(mktemp -d) && \
	trap "rm -rf $$TDIR" EXIT; \
	tar xzf dist/$(DISTFILE) -C $$TDIR && \
	(cd $$TDIR/$(FULLVER) && make doc && make test && make dist) && \
	echo "All good, you can upload $(DISTFILE)!"

test:
	@set -e; \
	for ver in 3.7 3.8 3.9 3.10 3.11 3.12; do \
	  for flavour in "" "-dbg"; do \
	    if type python$$ver$$flavour >/dev/null; then \
	      echo Testing with python$$ver$$flavour; \
	      python$$ver$$flavour ./setup.py build_ext -i; \
	      python$$ver$$flavour -m pytest tests ;\
	    fi; \
	  done; \
	done; \
	for pp in pypy3; do \
	  if type $$pp >/dev/null; then \
	    echo Testing with $$pp; \
	    $$pp ./setup.py build_ext -i; \
	    $$pp -m pytest tests; \
	  fi; \
	done

fast-test:
	python3 setup.py build_ext -i
	python3 -m pytest tests

ci:
	while inotifywait -e CLOSE_WRITE tests/test_*.py; do \
	  python3 -m pytest tests; \
	done

coverage:
	$(MAKE) clean
	$(MAKE) test CFLAGS="-coverage"
	lcov --capture --no-external --directory . --output-file coverage.info
	genhtml coverage.info --output-directory out

clean:
	rm -rf $(DOCHTML) $(DOCTREES)
	rm -f $(MODNAME)
	rm -f *.so
	rm -rf build

types:
	MYPYPATH=. mypy --check-untyped-defs --warn-incomplete-stub tests/test_acls.py

.PHONY: doc test clean dist coverage ci types
