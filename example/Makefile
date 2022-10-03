.PHONY: all
all: example

# This rule tells make how to build hello from hello.cpp
example: src/example.c
	clang -o src/example src/example.c -save-temps=obj -g -pie -fPIE

# This rule tells make to delete hello and hello.o
.PHONY: clean
clean:
	rm src/*.s src/example
