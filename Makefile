
all: memlockd

WFLAGS=-Wall -W -Wshadow -Wpointer-arith -Wcast-align -Wwrite-strings -Wcast-qual -pedantic -ffor-scope


memlockd: memlockd.cpp
	g++ -O2 memlockd.cpp -o memlockd $(WFLAGS)

clean:
	rm -f memlockd
