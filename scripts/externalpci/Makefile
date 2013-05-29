CFLAGS= -flto -std=c11 -g -O3 -march=native -I../../include -pthread -Wall -Wextra 

all: virtio-server

virtio-server: externalpci-server.o virtio.o iov.o
	$(CC) $(CFLAGS) -o $@ $+

.PHONY: clean
clean:
	rm -f *~ *.o virtio-server

