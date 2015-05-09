CC      = clang
AR      = ar
CFLAGS  = -O2 -Wall -Werror -std=c99 -pedantic -I.

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


# Install/uninstall the header and library.
INSTALL_PREFIX=/usr/local

install: build/libnectar.a
	@printf "   cp  $(INSTALL_PREFIX)/include/nectar.h\n"
	@cp include/nectar.h "$(INSTALL_PREFIX)/include/nectar.h"
	@printf "   cp  $(INSTALL_PREFIX)/lib/libnectar.a\n"
	@cp build/libnectar.a "$(INSTALL_PREFIX)/lib/libnectar.a"

uninstall:
	@printf "   rm  $(INSTALL_PREFIX)/include/nectar.h\n"
	@rm -f $(INSTALL_PREFIX)/include/nectar.h
	@printf "   rm  $(INSTALL_PREFIX)/lib/libnectar.a\n"
	@rm -f $(INSTALL_PREFIX)/lib/libnectar.a


.PHONY: build clean install uninstall
