CXX=g++
CXX_FLAGS=-W -std=c++17
LIBS=-lpthread -lssl -lcrypto
LD_FLAGS=-g
TARGET=test

security.o: security.cpp security.hpp byte_array.hpp
	$(CXX) -c security.cpp $(CXX_FLAGS)

main.o: main.cpp
	$(CXX) -c main.cpp $(CXX_FLAGS)

all: security.o main.o
	$(CXX) -o $(TARGET) security.o main.o $(LD_FLAGS) $(LIBS)

clean:
	rm -rf *.o $(TARGET)
