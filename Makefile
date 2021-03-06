CC = g++

CFLAGS  = -Wall -lpcap

# The build target 
TARGET = ipk-sniffer

all: $(TARGET)

$(TARGET): $(TARGET).cpp
		$(CC) $(CFLAGS) -o $(TARGET) $(TARGET).cpp

clean:
		$(RM) $(TARGET)

run: $(TARGET)
	./$(TARGET)

