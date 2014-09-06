obj-m := sbrack.o
sbrack-objs := kmanage.o main.o

all: sbrack

sbrack:
	make -Wall -Werror -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
