# vim: set noexpandtab:
# 
# A simple implementation of DES (Data Encryption Algorithm)
#
# Sun Dec 20 14:19:33 IST 2009
# Aniruddha. A (aniruddha.a@gmail.com)
#  

CC = gcc
CFLAGS = -Wall -g -ggdb # -O2  # Wall is life saver, dont forget
OBJECTS = getopts.o flblkread.o des.o
#LINKOPTS = -lefence
all : des

des : $(OBJECTS)
	$(CC) $(CFLAGS) $(OBJECTS) $(LINKOPTS) -o $@ 

%.o : %.c
	$(CC) $(CFLAGS) -c $<
clean:
	@rm -f $(OBJECTS) des.tgz des
pkg:
	@tar zcvf des.tgz Makefile \
	   	  README \
		  *.[ch] \
		  *.dat  \
		  regress.pl
