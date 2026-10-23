CC      = gcc
CFLAGS  = -Wall -Wextra -g -std=gnu99 -MMD -MP
SRCS    = $(wildcard src/*.c)
OBJS    = $(SRCS:.c=.o)
TARGET  = bin/master

all: $(TARGET) copy-config

$(TARGET): $(OBJS)
	@mkdir -p bin
	$(CC) $(CFLAGS) -o $@ $^
	
copy-config: $(TARGET)
	cp config/*.txt bin/	

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)

.PHONY: all clean copy-config
-include $(OBJS:.o=.d)   
