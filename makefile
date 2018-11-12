INC = -I/usr/local/lib/pbc -I/usr/include/pbc -I/usr/local/include/pbc -I/usr/local/Cellar/pbc/0.5.14/include/pbc
 
all: example example2 example3

example: commitment.c
	gcc commitment.c example.c $(INC) -o example -L . -lgmp -lpbc -lsodium

example2: commitment.c
	gcc commitment.c example2.c $(INC) -o example2 -L . -lgmp -lpbc -lsodium

example3: commitment.c
	gcc commitment.c example3.c $(INC) -o example3 -L . -lgmp -lpbc -lsodium

clean: 
	rm example example2 example3