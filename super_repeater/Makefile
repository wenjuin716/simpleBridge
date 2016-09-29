# Comment/uncomment the following line to disable/enable debugging
#DEBUG = y


# Add your debugging flag (or not) to CFLAGS
ifeq ($(DEBUG),y)
  DEBFLAGS = -O -g -DSBULL_DEBUG # "-O" is needed to expand inlines
else
  DEBFLAGS = -O2
endif

EXTRA_CFLAGS += $(DEBFLAGS)
EXTRA_CFLAGS += -I..

ifeq ($(C55),)

ifeq ($(KERNELPATH), )
        KERNELPATH := ../../../linux-2.6.36.x/
endif

obj-m := super_repeater.o

all:
	$(MAKE) -C $(KERNELPATH) M=`pwd` modules
	mipsel-linux-strip --strip-unneeded super_repeater.ko
else
ifneq ($(KERNELRELEASE),)
# call from kernel build system

obj-m	:= snull.o

else

KERNELDIR ?= /lib/modules/$(shell uname -r)/build
PWD       := $(shell pwd)

default:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules

endif
endif


clean:
	rm -rf *.o *~ core .depend .*.cmd *.ko *.mod.c .tmp_versions

depend .depend dep:
	$(CC) $(EXTRA_CFLAGS) -M *.c > .depend


ifeq (.depend,$(wildcard .depend))
include .depend
endif
