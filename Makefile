#CFLAGS = -Wall -W -g -O0
CFLAGS = -Wall -W -O2

all: mccat

clean:
	rm -f *.o mccat

mccat: mccat.o
	$(CC) -o $@ $^

.PHONY: all clean
