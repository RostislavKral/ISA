# @author Rostislav Kral

CXX = g++
CXXFLAGS = -std=c++14 -Wall

TARGET = dns
SOURCES = main.cpp helpers.cpp dns-resolver.cpp
OBJECTS = $(SOURCES:.cpp=.o)
HEADER_FILES = dns-resolver.h helpers.h


GTEST_DIR = googletest/googletest
GMOCK_DIR = googletest/googlemock
GMOCK_INC = -I$(GMOCK_DIR)/include
GTEST_INC = -I$(GTEST_DIR)/include
GTEST_LIB = -L googletest/lib -lgtest -lgtest_main -pthread
GMOCK_LIB = -L googlemock/lib -lgmock -lgmock_main

all: $(TARGET)

my_tests: clean tests.cpp
	cd googletest && rm CMakeCache.txt && cmake . && make
	g++ -std=c++14 -Wall -o my_tests tests.cpp $(HEADER_FILES) helpers.cpp dns-resolver.cpp $(GTEST_INC) $(GTEST_LIB) $(GMOCK_INC) $(GMOCK_LIB)

test: my_tests
	./my_tests
	rm -f my_tests


$(TARGET): $(OBJECTS) $(HEADER_FILES)
	$(CXX) $(CXXFLAGS) -o $@ $(OBJECTS)
	rm -f $(OBJECTS)


.PHONY: clean

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -f $(OBJECTS) $(TARGET) my_tests
