COMPILER = g++
CFLAGS = -Wall -ggdb -O0
INCL_PATHS =

all: server

server: main.cpp server.o
	$(COMPILER) -std=c++20 $(INCL_PATHS) $^ -o $@ $(CFLAGS)

server.o: server.cpp server.h helper.o
	$(COMPILER) -std=c++20 $(INCL_PATHS) -c $< -o $@ $(CFLAGS)

helper.o: helper.hpp
	$(COMPILER) -std=c++20 $(INCL_PATHS) -c $< -o $@ $(CFLAGS)

clean:
	rm -rf server
	rm -rf *.o
	rm -rf *.dSYM
