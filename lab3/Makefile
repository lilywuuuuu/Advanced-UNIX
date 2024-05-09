# Cross-compiler prefix
CROSS_COMPILE := x86_64-linux-gnu-

# Compiler and flags
CC := gcc
CFLAGS := -Wall -Wextra -pedantic -std=c11 -fPIC
LDFLAGS := -shared

LIB_SOURCES = libmaze_dummy.c
MAZE_SOURCES = maze.c
LIB_OBJECTS = $(LIB_SOURCES:.c=.o)
MAZE_OBJECTS = $(MAZE_SOURCES:.c=.o)
LIBRARY = libmaze.so
EXECUTABLE = maze

.PHONY: libsolver.so libersolver_x86.so clean all
all: $(LIBRARY) $(EXECUTABLE)

# Target
1: libmaze.so maze

2: libsolver.so

libmaze.so: libmaze_dummy.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

libsolver.so: libsolver.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

maze: maze.c
	$(CC) -o $@ $< -L. -lmaze -Wl,-rpath="."

# $(LIBRARY): $(LIB_OBJECTS)
# 	$(CC) $(LDFLAGS) -o $@ $^

# $(EXECUTABLE): $(MAZE_OBJECTS) $(LIBRARY)
# 	$(CC) -o $@ $^ -L. -lmaze

# %.o: %.c
# 	$(CC) $(CFLAGS) -c $< -o $@

# libsolver_x86.so: libsolver.c
# 	$(CROSS_COMPILE)$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

# libsolver.so: libsolver.c
# 	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

clean:
	rm -f libsolver.so $(LIB_OBJECTS) $(MAZE_OBJECTS) $(LIBRARY) $(EXECUTABLE)




