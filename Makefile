CC      = clang
AR      = ar
CFLAGS  = -O2 -Wall -Werror -std=c99 -pedantic -I./include

SOURCES = $(shell find src -type f -name "*.c")
OBJECTS = $(SOURCES:src/%.c=build/%.o)


# Default make target.
build: build/libnectar.a

# Assemble the static library.
build/libnectar.a: $(OBJECTS)
	@printf "   AR  $@\n"
	@$(AR) cr $@ $(OBJECTS)

# Build individual translation units.
build/%.o: src/%.c
	@printf "   CC  $@\n"
	@mkdir -p $(shell dirname $@)
	@$(CC) -MM $(CFLAGS) $< | sed -e 's|^\(.*\):|build/\1:|' > $(@:.o=.d)
	@$(CC) $(CFLAGS) -c -o $@ $<

-include $(OBJECTS:%.o=%.d)


# Empty the build/ directory.
clean:
	@printf "   rm  build/*\n"
	@rm -rf build/*


# Install header and library.
install: build/libnectar.a
	@printf "   cp  /usr/local/include/nectar.h\n"
	@cp include/nectar.h "/usr/local/include/nectar.h"
	@printf "   cp  /usr/local/lib/libnectar.a\n"
	@cp build/libnectar.a "/usr/local/lib/libnectar.a"

# Uninstall header and library.
uninstall:
	@printf "   rm  /usr/local/include/nectar.h\n"
	@rm -f /usr/local/include/nectar.h
	@printf "   rm  /usr/local/lib/libnectar.a\n"
	@rm -f /usr/local/lib/libnectar.a


.PHONY: build clean install uninstall
