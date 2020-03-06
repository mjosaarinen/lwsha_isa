//	bools.c
//	2020-03-02	Markku-Juhani O. Saarinen <mjos@pqshield.com>

#include <stdio.h>
#include <string.h>

#define OP_XOR	0
#define OP_AND	1
#define OP_OR	2
#define OP_ANDN	3

int op2(int x, int y, int op)
{
	switch(op) {
		case OP_XOR:
			return x ^ y;

		case OP_AND:
			return x & y;

		case OP_OR:
			return x | y;

		case OP_ANDN:
			return ~x ^ y;
	}

	return 0;
}


/*
   x   y
	\ /  
     O   z
      \ /
       O
*/

int op3t1(int x, int y, int z, int op)
{
	int t;

	t = op2(x, y, op & 3);
	return op2(t, z, (op >> 2) & 3);
}


/* 
   x   y   z
	\ / \ /
     O   O
      \ /
       O
*/

int op3t2(int x, int y, int z, int op)
{
	int t, u;

	t = op2(x, y, op & 3);
	u = op2(y, z, (op >> 2) & 3);

	return op2(t, u, (op >> 4) & 3);
}



/* 
   x   y
	\ /
     O   z
     |\ /
     \ O  
      \|
	   O
*/

int op3t3(int x, int y, int z, int op)
{
	int t, u;

	t = op2(x, y, op & 3);
	u = op2(t, z, (op >> 2) & 3);

	return op2(t, u, (op >> 4) & 3);
}

int ch(int x, int y, int z)
{
	return (x & y) ^ (~x & z);
}

int ch2(int x, int y, int z)
{
	return ((x ^ y) & z) ^ y;
}


int maj(int x, int y, int z)
{
	return (x & y) ^ (x & z) ^ (y & z);
}

int maj2(int x, int y, int z)
{
	return ((z | x) & y) | (z & x);
}

int bools()
{
	int x, y, z;

	for (x = 0; x < 2; x++) {
		for (y = 0; y < 2; y++) {
			for (z = 0; z < 2; z++) {

				printf("%d%d%d:", x, y, z);

				printf(" ch=%d%d", ch(x,y,z), ch2(y,x,z));
				printf(" maj=%d%d", maj(x,y,z), maj2(x,y,z));


				printf("\n");			
			}
		}
	}


	return 0;
}
