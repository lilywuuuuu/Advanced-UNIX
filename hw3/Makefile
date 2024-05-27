# Define the compiler
CXX = g++

# Define the compiler flags
CXXFLAGS = -std=c++11 -Wall -Wextra

# Define the linker flags
LDFLAGS = -lcapstone

# Define the target executable
TARGET = sdb

# Define the source files
SRCS = sdb.cpp

# Define the object files
OBJS = $(SRCS:.cpp=.o)

# Default target
all: $(TARGET)

# Rule to link the target executable
$(TARGET): $(OBJS)
	$(CXX) -o $(TARGET) $(OBJS) $(LDFLAGS)

# Rule to compile the source files
%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Rule to clean the build
clean:
	rm -f $(OBJS) $(TARGET)

# Phony targets
.PHONY: all clean