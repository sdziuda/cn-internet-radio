CFLAGS = -Wall -O2 -std=c++20 -I/usr/local/boost_1_82_0
CC = g++
PO_FILE = /usr/local/boost_1_82_0/libs/program_options/build/libboost_program_options.a

all: sikradio-receiver sikradio-sender

sikradio-receiver: sikradio-receiver.o
	$(CC) $(CFLAGS) -o $@ $^ $(PO_FILE)

sikradio-sender: sikradio-sender.o
	$(CC) $(CFLAGS) -o $@ $^ $(PO_FILE)

.cpp.o:
	$(CC) $(CFLAGS) -c $<

clean:
	rm -f *.o sikradio-receiver sikradio-sender