CC      = clang
CFLAGS  = -I./include -O2 -std=c99 -pedantic -Wall -Werror
AR      = ar

TARGET  = build/libnectar.a
OBJECTS = build/25519/fe.o                                                     \
          build/25519/ge.o                                                     \
          build/25519/sc.o                                                     \
          build/bcmp.o                                                         \
          build/chacha20.o                                                     \
          build/curve25519.o                                                   \
          build/ed25519.o                                                      \
          build/pbkdf2.o                                                       \
          build/poly1305.o                                                     \
          build/sha512.o

-include $(OBJECTS:%.o=%.d)

$(TARGET): $(OBJECTS)
	@printf "   AR  $@\n"
	@$(AR) cr $@ $(OBJECTS)

build/%.o: src/%.c
	@printf "   CC  $@\n"
	@mkdir -p $(shell dirname $@)
	@$(CC) -MM $(CFLAGS) $< | sed -e 's/^\(.*\):/build\/\1:/' > $(@:.o=.d)
	@$(CC) $(CFLAGS) -c -o $@ $<

clean:
	@printf "   rm  build/*\n"
	@rm -rf build/*

.PHONY: clean
