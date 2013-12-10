
all: memlockd

WFLAGS=-Wall -W -Wshadow -Wpointer-arith -Wcast-align -Wwrite-strings -Wcast-qual -pedantic -ffor-scope


memlockd: memlockd.cpp
	gcc -O2 memlockd.cpp -o memlockd $(WFLAGS) -lstdc++

clean:
	rm -f memlockd
