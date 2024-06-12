CC = gcc
LIBS = -lpcap

SRCS = main.c
OBJS = $(SRCS:.c=.o)
TARGET = tcp-block

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) -o $@ $^ $(LIBS)

.c.o:
	$(CC) -c -o $@ $<

clean:
	rm -f $(TARGET) $(OBJS)
