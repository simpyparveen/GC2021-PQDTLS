#ifndef KSNMSS_H_
#define KSNMSS_H_


#include "merkle-tree.c"
#include "1cff.c"

#define seedlen 32
#define k2sn_msglen 32
#define ivlen 8
int updateiter = hlength/2-1;
u8 system_seed[seedlen];
u8 system_iv[ivlen];	
u8 randompad_seed[seedlen];
u8 randompad_iv[ivlen];

sk_node random_pad[hlength+llength];
node auth[hlength];
node keep[hlength-1];
node retain;
node MSSPK;


// sizeof ksnmss_sig : 21364
typedef struct signature{
	u32 id; //4 bytes
	u8 message[k2sn_msglen]; //32 bytes
	u8 sksum[sklen*8]; //128*8 =1024 Bytes
	node pk[k2sn_t]; //262 nodes = 262 * 72 = 18864 bytes
	node auth[hlength]; //20 nodes = 20 *72 = 1440 bytes
}ksnmss_sig;


typedef struct rg_elm{
	u32 key[rglen];
}rg_elm;

const u8 enc_one[sklen]={1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
                     0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
const u8 enc_two[sklen]={2,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
       	    	     0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};

void system_setup();
void generate_secret_key_OTS(ECRYPT_ctx *seed_ctx, u8 *idu8, sk_node *sk);
void generate_public_key_OTS(sk_node *sk, node *pk, vec A[16][4]);
void key_generation(u8 *system_seed, u8 *system_iv);
node create_L_tree(node *pk, u32 id);
void pn(node *r);

void ksnmss_sign(u32 id, u8 *ms, ksnmss_sig *sig);
int ksnmss_verify(u32 id, u8 *ms, ksnmss_sig *sig);
void convert_ring(u8 *rg8, rg_elm *a);
void set_random_pad(u32 indx, u32 height, u8 randpad[sklen]);
#endif
