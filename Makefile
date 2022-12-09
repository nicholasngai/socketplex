TARGETS = \
	socketplexrecv \
	socketplexsend
DEPS = $(TARGETS:=.d)

CPPFLAGS = -MMD
CFLAGS = -std=c11 -pedantic -pedantic-errors -Wall -Wextra -O3
LDFLAGS =
LDLIBS =

.PHONY: all
all: $(TARGETS)

.PHONY: clean
clean:
	rm -rf $(TARGETS)

-include $(DEPS)
