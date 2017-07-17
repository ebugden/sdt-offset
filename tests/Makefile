CC = gcc
CFLAGS = -g -Wall -O0

all: function-test sdt-no-probe sdt-probe

function-test: function-test.o
	$(CC) $(CFLAGS) -o function-test function-test.c

sdt-no-probe: sdt-no-probe.o
	$(CC) $(CFLAGS) -o sdt-no-probe sdt-no-probe.c

sdt-probe: sdt-probe.o
	$(CC) $(CFLAGS) -o sdt-probe sdt-probe.c

clean:
	rm function-test sdt-no-probe sdt-probe *.o

