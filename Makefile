CC64 ?= x86_64-w64-mingw32-gcc
CC32 ?= i686-w64-mingw32-gcc
STRIP64 ?= x86_64-w64-mingw32-strip
STRIP32 ?= i686-w64-mingw32-strip
CPPFLAGS := -I include
CFLAGS := -std=gnu11 -Os -DBOF -mno-stack-arg-probe \
	-Wall -Wextra -Werror -Wno-int-conversion -Wno-incompatible-pointer-types

.PHONY: all clean

all: bin/winrm_pth.x64.o bin/winrm_pth.x32.o

bin/winrm_pth.x64.o: src/winrm_pth.c include/beacon.h include/ntlm_auth.h include/ntlm_session.h
	@mkdir -p bin
	$(CC64) $(CPPFLAGS) $(CFLAGS) -c $< -o $@
	$(STRIP64) --strip-unneeded $@

bin/winrm_pth.x32.o: src/winrm_pth.c include/beacon.h include/ntlm_auth.h include/ntlm_session.h
	@mkdir -p bin
	$(CC32) $(CPPFLAGS) $(CFLAGS) -c $< -o $@
	$(STRIP32) --strip-unneeded $@

clean:
	$(RM) -r bin
