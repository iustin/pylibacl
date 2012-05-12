SPHINXOPTS    =
SPHINXBUILD   = sphinx-build
DOCDIR        = doc
DOCHTML       = $(DOCDIR)/html
DOCTREES      = $(DOCDIR)/doctrees
ALLSPHINXOPTS = -d $(DOCTREES) $(SPHINXOPTS) $(DOCDIR)

MODNAME = posix1e.so

all: doc test

$(MODNAME): acl.c
	./setup.py build_ext --inplace

doc: $(MODNAME)
	$(SPHINXBUILD) -b singlehtml $(ALLSPHINXOPTS) $(DOCHTML)

test:
	for ver in 2.4 2.5 2.6 3.0 3.1; do \
	  if type python$$ver >/dev/null; then \
	    echo Testing with python$$ver; \
	    python$$ver ./setup.py test; \
          fi; \
	done

clean:
	rm -rf $(DOCHTML) $(DOCTREES)
	rm -f $(MODNAME)
	rm -rf build

.PHONY: doc test clean
