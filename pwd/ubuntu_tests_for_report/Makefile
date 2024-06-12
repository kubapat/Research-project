CC = gcc
CFLAGS = -Wall -Wextra -std=c99
LIBS = -lseccomp

TARGET = pwd_seccomp_monitor
SRCS = pwd_seccomp_monitor.c

all: $(TARGET)

$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRCS) $(LIBS)

clean:
	rm -f $(TARGET)

.PHONY: all clean
