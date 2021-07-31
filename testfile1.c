//
// Created by Simpy Parveen on 2020-03-09.
//
#include <stdio.h>
#include <stdlib.h>

/**Set public key in a fi;le and read from the same file*/

void main() {
//memcpy(MSSPK.key,treestack[top].key,pklen);
    printf("\n Check : Adding public Key\n");
    FILE *fw, *fr;
    ssize_t result = 0;
    int pklen=100;
    const char *public_key_filename = "publicKeyMSS.pub";
    unsigned char *public_key = malloc(pklen);
    unsigned char *public_key2 = malloc(pklen);
    //pn(MSSPK.key);
    memcpy(public_key, "Hello", 10);
    fw = fopen(public_key_filename, "w");


    if (fw == NULL)printf("\n Write error ! \n");
        //return -1;

    if (1 != fwrite(public_key, 1, pklen, fw)) {
        /* Write failed */
        printf("\n Write failed fw = %d \n", fw);
        fclose(fw);
        free(public_key);
        printf("\n public_key after free()\n");
        for (int i = 0; i < pklen; i++)
            printf("%hhu ", public_key[i]);
    }
    fr = fopen(public_key_filename, "r");
    int nfread = fread(public_key2, 1, pklen, fr);
    printf("\n public_key after read() bytes %d\n", nfread);
    for (int i = 0; i < pklen; i++)
        printf("%hhu ", public_key2[i]);

    fclose(fr);
    free(public_key2);

}