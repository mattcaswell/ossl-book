#Location of the openssl version we are using. May not be the same as the system
#version
OSSLDIR= /usr/local/ssl
CC= gcc
CFLAGS= -I$(OSSLDIR)/include -L$(OSSLDIR)/lib -g -lcrypto -lssl

EXE= devel-tls/get-start/simpleclient devel-tls/get-start/simpleclient2 \
	devel-tls/get-start/simpleserver

BOOKELEMS= ossl-dev-book.tex \
	introduction/getting/getting.tex \
	devel-tls/understand-tls/understand-tls.tex \
	devel-tls/get-start/get-start.tex

all: ossl-dev-book.pdf 

$(EXE): %: %.c
	$(CC) -o $@ $< $(CFLAGS)

#We run this twice to ensure that any references etc are updated
ossl-dev-book.pdf: $(BOOKELEMS) $(EXE)
	pdflatex ossl-dev-book
	pdflatex ossl-dev-book

code: $(EXE)

clean-code:
	rm $(EXE)

clean-book:
	rm ossl-dev-book.pdf ossl-dev-book.log

clean: clean-book clean-code
