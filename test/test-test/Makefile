# Sample Makefile for Capstone Disassembly Engine

LIBNAME = capstone


test: test1.c test1.h ../../lib/vex/pub/*.h ../../lib/vex/priv/*.c ../../lib/vex/priv/*.h
	(cd ../../lib/vex/; make -f Makefile-gcc;)
	gcc -I../../lib/vex/pub -o $@ test1.c ../../lib/vex/libvex.a -O3 -Wall -l$(LIBNAME)


clean:
	rm -f ../../lib/vex/priv/*.o