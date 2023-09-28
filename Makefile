CXX = g++
CXXFLAGS = -std=c++11 -Wall

TARGET = dns
SOURCES = main.cpp
OBJECTS = $(SOURCES:.cpp=.o)

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CXX) $(CXXFLAGS) -o $@ $^
	rm -f $(OBJECTS)  # Smazání objektových souborů po úspěšném sestavení

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c -o $@ $<

clean:
	rm -f $(OBJECTS) $(TARGET)

run:
	./dns
