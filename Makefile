all:
	gcc -o bin/udpblast src/udpblast.c -lpthread
clean:
	@rm -f bin/udpblast
