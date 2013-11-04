
ifeq ($(KERNELRELEASE),)

src := /lib/modules/$(shell uname -r)/source
pwd := $(shell pwd)

all:
	make -C $(src) M=$(pwd) 

clean:
	make -C $(src) M=$(pwd) clean

else

obj-m := a.o

endif

