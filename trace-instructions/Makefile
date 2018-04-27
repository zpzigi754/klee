PINDIR = $(HOME)/pin

default: pin-trace.so

pin-trace.o: pin-trace.cpp
	g++ -Wall -Werror -Wno-unknown-pragmas -std=c++11 \
	    -D__PIN__=1 -DPIN_CRT=1 \
	    -fno-stack-protector -fno-exceptions -funwind-tables -fasynchronous-unwind-tables -fno-rtti \
	    -DTARGET_IA32E -DHOST_IA32E -fPIC -DTARGET_LINUX -fabi-version=2 \
	    -I$(PINDIR)/source/include/pin -I$(PINDIR)/source/include/pin/gen \
	    -isystem $(PINDIR)/extras/stlport/include \
	    -isystem $(PINDIR)/extras/libstdc++/include \
	    -isystem $(PINDIR)/extras/crt/include \
	    -isystem $(PINDIR)/extras/crt/include/arch-x86_64 \
	    -isystem $(PINDIR)/extras/crt/include/kernel/uapi \
	    -isystem $(PINDIR)/extras/crt/include/kernel/uapi/asm-x86 \
	    -I$(PINDIR)/extras/components/include \
	    -I$(PINDIR)/extras/xed-intel64/include/xed \
	    -I$(PINDIR)/source/tools/InstLib \
	    -O3 -fomit-frame-pointer -fno-strict-aliasing \
	    -c -o $@ $<

pin-trace.so: pin-trace.o
	g++ -shared -Wl,--hash-style=sysv \
	    $(PINDIR)/intel64/runtime/pincrt/crtbeginS.o \
	    -Wl,-Bsymbolic \
	    -Wl,--version-script=$(PINDIR)/source/include/pin/pintool.ver \
	    -fabi-version=2 \
	    -o $@ $< \
	    -L$(PINDIR)/intel64/runtime/pincrt \
	    -L$(PINDIR)/intel64/lib \
	    -L$(PINDIR)/intel64/lib-ext \
	    -L$(PINDIR)/extras/xed-intel64/lib \
	    -lpin -lxed \
	    $(PINDIR)/intel64/runtime/pincrt/crtendS.o \
	    -lpin3dwarf -ldl-dynamic -nostdlib -lstlport-dynamic -lm-dynamic -lc-dynamic -lunwind-dynamic

clean:
	rm -f pin-trace.so pin-trace.o
