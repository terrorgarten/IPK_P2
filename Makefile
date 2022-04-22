CC = g++

CFLAGS  = -Wall

# The build target 
TARGET = sniffer

all: $(TARGET)

$(TARGET): $(TARGET).cpp
		$(CC) $(CFLAGS) -o $(TARGET) $(TARGET).cpp

clean:
		$(RM) $(TARGET)

run: $(TARGET)
	./$(TARGET)

