TARGET = socketplex
OBJS = socketplex.o
DEPS = $(OBJS:=.d)

CPPFLAGS = -MMD
CFLAGS = -std=c11 -pedantic -pedantic-errors -Wall -Wextra -O3 -ggdb -g3
LDFLAGS =
LDLIBS =

.PHONY: all
all: $(TARGET)

$(TARGET): $(OBJS)

.PHONY: clean
clean:
	rm -rf $(TARGET)

-include $(DEPS)
