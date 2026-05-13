# Build the paper. Requires a full TeX Live install (pdflatex + bibtex).
#
# Usage:
#   make           # produces paper.pdf
#   make clean     # remove aux files
#   make distclean # remove aux + pdf

TEX     := pdflatex
BIB     := bibtex
PAPER   := paper

.PHONY: all clean distclean

all: $(PAPER).pdf

$(PAPER).pdf: $(PAPER).tex refs.bib
	$(TEX) -interaction=nonstopmode $(PAPER).tex
	$(BIB)  $(PAPER)
	$(TEX) -interaction=nonstopmode $(PAPER).tex
	$(TEX) -interaction=nonstopmode $(PAPER).tex

clean:
	rm -f *.aux *.log *.out *.toc *.bbl *.blg *.synctex.gz

distclean: clean
	rm -f $(PAPER).pdf
