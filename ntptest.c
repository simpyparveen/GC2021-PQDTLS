   ///Testing
#include<stdio.h>
#include <stdint.h>
int main()
{
    printf("\nOnly for testing :\n");
    ///Testing
    struct timeval tv,tv2;
    uint8_t *pp;

    uint8_t * ss = malloc(16);
    uint8_t * ss1 = malloc(8);
    uint8_t * ss2 = malloc(8);

    uint64_t t1,t2;

    gettimeofday(&tv, NULL);
    printtime(tv);


    //u64 value to u8*
    dtls_int_to_uint64(ss,tv.tv_sec);
    pp=ss;
    ss += 8;
    dtls_int_to_uint64(ss,tv.tv_usec);

//                //saved in u8
//                   memcpy(&ss,tv.tv_sec,8);
//                   memcpy(&ss+8,tv.tv_usec,8);

//                for(int i =0; i < 16; ++i)
//                {
//                    ss[i] = 0;
//
//                }
    //ss1 and ss2
    memcpy(ss1,pp,8);
    memcpy(ss2,pp+8,8);
//
//                //u8* to u64
    t1=dtls_uint64_to_int(ss1);//dtls_uint64_to_int(ss1);
    t2=dtls_uint64_to_int(ss2);

    //  dtls_uint64_to_int(ss1);
    /*  t2 = dtls_uint64_to_int(ss2);
        //back to timeval
       memcpy(tv2.tv_sec,ss1,8);
        memcpy(tv2.tv_usec,ss2,8);*/
/////
//               t1=((uint64_t)ss1[0] << 56)
//                | ((uint64_t)ss1[1] << 48)
//                | ((uint64_t)ss1[2] << 40)
//                | ((uint64_t)ss1[3] << 32)
//                | ((uint64_t)ss1[4] << 24)
//                | ((uint64_t)ss1[5] << 16)
//                | ((uint64_t)ss1[6] << 8)
//                | (uint64_t)ss1[7];
//
//                t2=((uint64_t)ss2[0] << 56)
//                   | ((uint64_t)ss2[1] << 48)
//                   | ((uint64_t)ss2[2] << 40)
//                   | ((uint64_t)ss2[3] << 32)
//                   | ((uint64_t)ss2[4] << 24)
//                   | ((uint64_t)ss2[5] << 16)
//                   | ((uint64_t)ss2[6] << 8)
//                   | (uint64_t)ss2[7];


    printf("\ntesting Tv2 ");
    tv2.tv_sec = t1;
    tv2.tv_usec = t2;
//                memcpy(&tv2.tv_sec,t1,8);
//                memcpy(&tv2.tv_usec,t2,8);
////
//
//
    printf("\nt1: %ld \n",t1);
    printf("\nt2: %d \n",t2);

    printtime(tv2); //
//
//


    free(ss1);
    free(ss2);
    free(pp);


    return 0;
}
