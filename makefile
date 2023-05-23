CFLAGS = -Wall -O2 -std=c++20 -pthread -I/usr/local/boost_1_82_0
CC = g++
PO_FILE = -lboost_program_options

all: sikradio-receiver sikradio-sender

sikradio-receiver: sikradio-receiver.o $(PO_FILE)
	$(CC) $(CFLAGS) -o $@ $^

sikradio-sender: sikradio-sender.o $(PO_FILE)
	$(CC) $(CFLAGS) -o $@ $^

.cpp.o:
	$(CC) $(CFLAGS) -c $<

clean:
	rm -f *.o sikradio-receiver sikradio-sender