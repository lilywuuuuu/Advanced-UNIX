 
obj-m     += mazemod.o
ccflags-y += -DEXPORT_SYMTAB

all: maze
	make -C ../dist/modulebuild M=$(PWD) modules

maze: maze.c
	$(CROSS_COMPILE)gcc -o $@ $< -Wall -static

clean:
	rm -f maze
	make -C ../dist/modulebuild M=$(PWD) clean

install: all
	mkdir -p ../rootfs/modules
	cp maze maze.ko ../rootfs/modules
