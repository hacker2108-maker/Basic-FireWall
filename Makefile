# Makefile for Advanced Firewall

# Compiler and flags
CC := gcc
CFLAGS := -Wall -Wextra -O2
KERNELDIR ?= /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

# Module name
MODULE := advanced_firewall
MODULE_KO := $(MODULE).ko

# Userspace tool
TOOL := firewallctl

# Kernel object files
obj-m := $(MODULE).o
$(MODULE)-objs := advanced_firewall.o

# Source files
SRCS := advanced_firewall.c

all: $(TOOL) $(MODULE_KO)

$(MODULE_KO): $(SRCS)
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules

$(TOOL): firewallctl.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) clean
	rm -f $(TOOL) *.o *~ *.ko *.mod.c modules.order Module.symvers

install: all
	sudo insmod $(MODULE_KO)
	sudo cp $(TOOL) /usr/local/bin/

uninstall:
	sudo rmmod $(MODULE) || true
	sudo rm -f /usr/local/bin/$(TOOL)

.PHONY: all clean install uninstall