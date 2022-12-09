TARGETS = \
	socketplexsend

CPPFLAGS =
CFLAGS = -std=c11 -pedantic -pedantic-errors -Wall -Wextra -O3
LDFLAGS =
LDLIBS =

.PHONY: all
all: $(TARGETS)

.PHONY: clean
clean:
	rm -rf $(TARGETS)
