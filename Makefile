
all: memlockd

WFLAGS=-Wall -W -Wshadow -Wpointer-arith -Wcast-align -Wwrite-strings -Wcast-qual -pedantic -ffor-scope


memlockd: memlockd.cpp
	$(CXX) $(WFLAGS) $(CXXFLAGS) $(LDFLAGS) memlockd.cpp -o memlockd

clean:
	rm -f memlockd
