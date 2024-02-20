all: encrypt decrypt

encrypt: encrypt.o io.o DES.o DESMagic.o
	gcc encrypt.o io.o DES.o DESMagic.o -o encrypt

decrypt: decrypt.o io.o DES.o DESMagic.o
	gcc decrypt.o io.o DES.o DESMagic.o -o decrypt

DESTest: DESMagic.o DES.o DESTest.o
	gcc DESMagic.o DES.o DESTest.o -o DESTest

encrypt.o: encrypt.c io.h DES.h
	gcc -Wall -std=c99 -g -c encrypt.c

decrypt.o: decrypt.c io.h DES.h
	gcc -Wall -std=c99 -g -c decrypt.c

io.o: io.c io.h DES.h DESMagic.h
	gcc -Wall -std=c99 -g -c io.c

DES.o: DES.c DES.h DESMagic.h
	gcc -Wall -std=c99 -g -c DES.c

DESMagic.o: DESMagic.c DESMagic.h
	gcc -Wall -std=c99 -g -c DESMagic.c

DESTest.o: DESTest.c DESMagic.h DES.h
	gcc -Wall -std=c99 -g -c DESTest.c

clean:
	rm -f encrypt decrypt DESTest
	rm -f io.o DES.o DESMagic.o DESTest.o
