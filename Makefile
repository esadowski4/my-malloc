# Makefile for My Malloc Implementation

# Compiler and flags
CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -pthread
DEBUG_FLAGS = -g -O0 -DDEBUG
RELEASE_FLAGS = -O2 -DNDEBUG

# Default configuration
ARENAL_SIZE ?= 4096
N_LISTS ?= 59

# Source files
SOURCES = myMalloc.c
HEADERS = myMalloc.h
OBJECTS = $(SOURCES:.c=.o)

# Target library
TARGET = libmymalloc.a

# Test programs (if any)
TEST_SOURCES = $(wildcard test*.c)
TEST_TARGETS = $(TEST_SOURCES:.c=)

# Default target
all: $(TARGET)

# Build the static library
$(TARGET): $(OBJECTS)
	@echo "Creating static library $@"
	ar rcs $@ $^

# Compile source files
%.o: %.c $(HEADERS)
	@echo "Compiling $<"
	$(CC) $(CFLAGS) $(RELEASE_FLAGS) -DARENA_SIZE=$(ARENAL_SIZE) -DN_LISTS=$(N_LISTS) -c $< -o $@

# Debug build
debug: CFLAGS += $(DEBUG_FLAGS)
debug: clean $(TARGET)
	@echo "Debug build complete"

# Build test programs
tests: $(TARGET) $(TEST_TARGETS)

test%: test%.c $(TARGET)
	@echo "Building test program $@"
	$(CC) $(CFLAGS) $(RELEASE_FLAGS) -o $@ $< -L. -lmymalloc

# Run basic tests
test: tests
	@echo "Running tests..."
	@for test in $(TEST_TARGETS); do \
		if [ -f $$test ]; then \
			echo "Running $$test"; \
			./$$test; \
		fi \
	done

# Profile build (for performance analysis)
profile: CFLAGS += -pg -O2
profile: clean $(TARGET)
	@echo "Profile build complete"

# Address sanitizer build (for debugging memory issues)
asan: CFLAGS += -fsanitize=address -fno-omit-frame-pointer
asan: clean $(TARGET)
	@echo "Address sanitizer build complete"

# Thread sanitizer build (for debugging threading issues)
tsan: CFLAGS += -fsanitize=thread
tsan: clean $(TARGET)
	@echo "Thread sanitizer build complete"

# Custom arena size build
BIGARENA_SIZE = 8192
bigarea: ARENAL_SIZE=$(BIGARENA_SIZE)
bigarea: clean $(TARGET)
	@echo "Built with arena size $(BIGARENA_SIZE)"

# Shared library build
shared: CFLAGS += -fPIC
shared: libmymalloc.so

libmymalloc.so: $(OBJECTS)
	@echo "Creating shared library $@"
	$(CC) -shared -o $@ $^

# Install library (requires root/sudo)
install: $(TARGET)
	cp $(TARGET) /usr/local/lib/
	cp $(HEADERS) /usr/local/include/
	ldconfig
	@echo "Library installed"

# Uninstall
uninstall:
	rm -f /usr/local/lib/$(TARGET)
	rm -f /usr/local/include/$(HEADERS)
	ldconfig
	@echo "Library uninstalled"

# Clean build files
clean:
	@echo "Cleaning build files"
	rm -f $(OBJECTS) $(TARGET) libmymalloc.so
	rm -f $(TEST_TARGETS)
	rm -f *.gch core gmon.out

# Deep clean (includes backup files)
deepclean: clean
	rm -f *~ .*~
	rm -rf *.dSYM

# Show configuration
config:
	@echo "Configuration:"
	@echo "  CC: $(CC)"
	@echo "  CFLAGS: $(CFLAGS)"
	@echo "  ARENA_SIZE: $(ARENAL_SIZE)"
	@echo "  N_LISTS: $(N_LISTS)"
	@echo "  Sources: $(SOURCES)"
	@echo "  Headers: $(HEADERS)"

# Help target
help:
	@echo "Available targets:"
	@echo "  all      - Build release version (default)"
	@echo "  debug    - Build with debug information"
	@echo "  profile  - Build with profiling support"
	@echo "  asan     - Build with address sanitizer"
	@echo "  tsan     - Build with thread sanitizer"
	@echo "  shared   - Build shared library"
	@echo "  tests    - Build test programs"
	@echo "  test     - Run tests"
	@echo "  bigarea  - Build with larger arena size"
	@echo "  install  - Install library system-wide"
	@echo "  clean    - Remove build files"
	@echo "  config   - Show current configuration"
	@echo "  help     - Show this help"

# Phony targets
.PHONY: all debug profile asan tsan shared tests test bigarea clean deepclean install uninstall config help
