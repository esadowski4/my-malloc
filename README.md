# My Malloc Implementation

A custom implementation of malloc, free, realloc, and calloc functions in C.

## Overview

This project implements a memory allocator that manages dynamic memory allocation using:
- Free list data structure for efficient memory management
- Block coalescing to reduce fragmentation
- Thread-safe operations using pthread mutex
- Configurable arena size and number of free lists
- Optional relative pointer support

## Features

- **Custom Memory Management**: Implements `my_malloc()`, `my_free()`, `my_realloc()`, and `my_calloc()`
- **Free List Organization**: Uses multiple free lists for different block sizes
- **Memory Coalescing**: Automatically merges adjacent free blocks
- **Thread Safety**: Protected with mutex locks for concurrent access
- **Debug Support**: Built-in debugging and validation features
- **Configurable Parameters**: Customizable arena size and list count

## Configuration

### Compile-time Options

- `ARENA_SIZE`: Size of memory arena (default: 4096 bytes)
- `N_LISTS`: Number of free lists (default: 59)
- `RELATIVE_POINTERS`: Enable relative pointer support (default: true)

### Environment Variables

- `MALLOC_DEBUG_COLOR`: Enable colored debug output

## Building

```bash
# Build with default settings
make

# Build with custom arena size
make CFLAGS="-DARENA_SIZE=8192"

# Build with debug information
make debug

# Clean build files
make clean
```

## Usage

```c
#include "myMalloc.h"

int main() {
    // Allocate memory
    void *ptr = my_malloc(100);
    
    // Reallocate
    ptr = my_realloc(ptr, 200);
    
    // Free memory
    my_free(ptr);
    
    return 0;
}
```

## Project Structure

- `myMalloc.h` - Header file with function declarations and data structures
- `myMalloc.c` - Implementation of memory allocation functions
- `Makefile` - Build configuration
- `README.md` - This documentation

## Implementation Details

### Data Structures

- **Header Structure**: Contains metadata for each memory block including size, allocation state, and free list pointers
- **Free Lists**: Array of sentinel nodes organizing free blocks by size
- **Fence Posts**: Special markers to prevent coalescing across chunk boundaries

### Memory Layout

```
[Header][User Data...]
```

### Allocation States

- `UNALLOCATED`: Block is free and available
- `ALLOCATED`: Block is in use
- `FENCEPOST`: Special boundary marker

## Testing

Run the allocator with various programs to test functionality:

```bash
# Test basic allocation
./test_program

# Test with debugging enabled
MALLOC_DEBUG_COLOR=1 ./test_program
```

## Performance Considerations

- Free list organization minimizes search time for appropriately sized blocks
- Immediate coalescing reduces external fragmentation
- Mutex protection ensures thread safety but may impact performance in highly concurrent scenarios

## License

This project is for educational purposes.
