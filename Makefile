TARGET=daredevil
PREFIX=/usr/local
RESOURCES=$(PREFIX)/share/daredevil/
CC=clang++
CFLAGS=-Wall -Wextra -std=c++11 -Ofast -g -DRESOURCES=\"$(RESOURCES)\"
LIBS=-fopenmp -lm 

OBJECTS = $(patsubst %.cpp, %.o, $(wildcard *.cpp))
HEADERS = $(wildcard *.h)


TARGET_OBJECTS=$(filter-out $(TEST).o, $(OBJECTS))

.PHONY: default all clean check install uninstall

all: $(TARGET)

%.o: %.cpp $(HEADERS)
	$(CC) $(CFLAGS) -c $< -o $@

$(TARGET): $(TARGET_OBJECTS)
	$(CC) $(TARGET_OBJECTS) $(CFLAGS) -o $@ $(LIBS)

clean:
	@-rm -f *.o daredevil

install:
	@cp $(TARGET) $(PREFIX)/bin/
	@mkdir -p $(RESOURCES)
	@cp -a LUT $(RESOURCES)

uninstall:
	@rm $(PREFIX)/bin/$(TARGET)
	@rm -rf $(PREFIX)/share/daredevil
