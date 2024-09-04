# Variables
TARGET = pam_split_token.so
OBJS = pam_split_token.o
CFLAGS = -fPIC -Wall
LDFLAGS = -shared
LIBS = -lpam

# Default target
all: $(TARGET)

# Compile the object file
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Link the shared library
$(TARGET): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS) $(LIBS)

# Clean up the build files
clean:
	rm -f $(OBJS) $(TARGET)
