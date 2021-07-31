#include "measurement.h"
#include <time.h>
#include "merkle-tree.h"
#include "ChaCha20/chacha.c"
#include "swifft16/swifft-avx2-16.c"
#include "ksnmss.c"
#include <x86intrin.h>
#include <time.h>



int main(){
	int i,j;
	clock_t t1,t2;
	int verified;
	
	printf("Initializing system seeds...\n");
		
	for(i=0;i<seedlen;i++) system_seed[i]=rand()%255;
	for(i=0;i<ivlen;i++) system_iv[i]=rand()%255;
	for(i=0;i<seedlen;i++) randompad_seed[i]=rand()%255;
	for(i=0;i<ivlen;i++) randompad_iv[i]=rand()%255;
	for(i=0;i<seedlen;i++) hk_seed[i]=rand()%255;
	for(i=0;i<ivlen;i++) hk_iv[i]=rand()%255;
	set_binotable();
	ECRYPT_ctx seed_ctx;
	ECRYPT_keysetup(&seed_ctx,randompad_seed,256,64);
	ECRYPT_ivsetup(&seed_ctx,randompad_iv);
	u8 rand_h[sklen]={1,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 
				0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,
                   		0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 
				0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0};

	for(i=0;i<(hlength+llength);i++){
		ECRYPT_encrypt_bytes(&seed_ctx,rand_h,random_pad[i].key,sklen);
		rand_h[0]=rand_h[0]+1;
	}
	
	for(i=0;i<1024;i++){
		a[i] = 0;
	}
	
	printf("Key Generation Phase...\n");
	t1 = clock();	
	for(i=0;i<10;i++)
		key_generation(system_seed, system_iv);
	t2 = clock() - t1;
	printf("Key Generation Time for 10 iterations:: %lfs\n",(double)t2/CLOCKS_PER_SEC);

	u32 id;
	u8 ms[k2sn_msglen];
	for(j=0;j<k2sn_msglen;j++) ms[j]=rand()%256;
	ksnmss_sig sig;
	t1 = clock();
	for(id=0;id<16;id++)//1000000
		ksnmss_sign(id, ms, &sig);
	t2 = clock() - t1;
	printf("Signing Time for 1000000 iterations: %lfs\n",(double)t2/CLOCKS_PER_SEC);

	t1 = clock();
	for(i=0;i<16;i++)//1000000
		verified=ksnmss_verify(id-1, ms, &sig);
	t2 = clock() - t1;
	printf("Verify Time for 1000000 iterations: %lfs\n",(double)t2/CLOCKS_PER_SEC);

	
	printf("Verify %d-th message: %d\n",id,verified);
	
	return 0;
}
