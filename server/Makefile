all:
	$(CXX) -O2 -Iinclude/ -o socketserver main.cpp -lpthread -lssl -lcrypto

clean:
	rm -f socketserver

run:
	./launch.sh

dependencies:
	apt-get install libasio-dev
