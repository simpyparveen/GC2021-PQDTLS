#ifndef MERKLE_TREE_H_
#define MERKLE_TREE_H_

#include <immintrin.h>

#include <stdio.h>
#include <stdlib.h>
//#include <malloc.h>
#include <string.h>
#include <inttypes.h>
#include <stdint.h>

#define sklen 128
#define pklen 72
#define rglen 64
#define ranlen 128
#define usr 1048576// 16//2^h
#define hlength 20//20 //must be even
#define llength 9//9
#define merlen (2*pklen-sklen)

typedef unsigned char uint8;
typedef unsigned long int uint32;

typedef unsigned char uint8;
extern int key_length;

//public key struct
typedef struct node{
	uint8 key[pklen]; //72 bytes
}node;


typedef struct mssnode{
	uint8 key[pklen];
	uint32 height;
	uint32 indx;
}mssnode;

//secret key struct
typedef struct sk_node{
	uint8 key[sklen];
}sk_node; 


typedef struct treehash{
	node	v;
	mssnode treestack[hlength-1];
	uint32	finalized;
	uint32 	startleaf;
	uint32	lowheight;
	int 	top;
	
}treehash;

treehash instance[hlength-2];


#endif
