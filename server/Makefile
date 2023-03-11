all:
	$(cxx) -O2 -Iinclude/ -o socketserver main.cpp -lpthread -lssl -lcrypto

clean:
	rm -f socketserver

dependencies:
	apt-get install libasio-dev
