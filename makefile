CC = gcc

ers: ERS.o 
	$(CC) -o ers ERS.o
ERS.o: ERS.c
	$(CC) -c ERS.c 

.INTERMIDIATE: ERS.o

clean:
	rm -f *.o 
