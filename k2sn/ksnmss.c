#include "ksnmss.h"
#define infy 999999

/**
 * Computes and sets MSSPK.
 */

void key_generation(u8 *system_seed, u8 *system_iv){
	u32	id_t,id;
	int j;
	u8 	idu8[seedlen]={0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0};
	sk_node sk[k2sn_t]; // t secret key struct each of 1024 bits
	node	pk[k2sn_t]; //t public key struct each of 576 bits
	node	leaf;
	sk_node	temp;
	int xbyte[16][4];
	mssnode treestack[hlength+1];
	mssnode nodestack;
	int 	top=-1; //Top of treestack
	u8	rdp[sklen];

    //Set up ChaCha key for generating secret component keys
	ECRYPT_ctx seed_ctx;
	ECRYPT_keysetup(&seed_ctx,system_seed,256,64);
	ECRYPT_ivsetup(&seed_ctx,system_iv);


    //Generate each OTS instance and build full merkle tree concurrently
	for(id=0;id<usr;id++){

        //idu8, id = index of this OTS instance
		id_t=id;
		idu8[0] = (u8)(id_t & 0xFF);	id_t = id_t >> 8;
		idu8[1] = (u8)(id_t & 0xFF);	id_t = id_t >> 8;
		idu8[2] = (u8)(id_t & 0xFF);	id_t = id_t >> 8;
		idu8[3] = (u8)(id_t & 0xFF);


        // Resets counter to 0
		ECRYPT_keysetup(&seed_ctx,system_seed,256,64);
		ECRYPT_ivsetup(&seed_ctx,system_iv);

        //Generate component keys of the OTS instance
		generate_secret_key_OTS(&seed_ctx, idu8, sk);

        //Generate and set SWIFFT key for hashing component keys of this OTS instance. The
        //SWIFFT key is put in the array 'A'.
		set_Key(id,0);

        //Public key component keys are computed and put in pk
		generate_public_key_OTS(sk, pk, A);

        //leaf is root of L_id tree
		leaf = create_L_tree(pk,id);


        //Compute portion of Merkle tree using algorithm similar to the TreeHash algorithm
        //described in "Optimal Paremeters of XMSS^MT". After the last iteration of this for
        //loop, treestack[top] will contain the root of the merkle tree
		memcpy(nodestack.key, leaf.key,pklen);
		nodestack.height = 0;
		nodestack.indx = id;

		while((top!=-1) && (treestack[top].height==nodestack.height)){
			if (nodestack.indx == 1)
				memcpy(auth[nodestack.height].key, nodestack.key,pklen);

			if (nodestack.indx == 3){
				if(nodestack.height < (hlength-2)){
					memcpy((instance[nodestack.height].v).key, nodestack.key,pklen);
					instance[nodestack.height].finalized = 1;
					instance[nodestack.height].lowheight = infy;
					instance[nodestack.height].top = -1;
				}else if (nodestack.height == (hlength-2)){
					memcpy(retain.key, nodestack.key,pklen);
				}
			}
			set_random_pad(nodestack.indx/2,nodestack.height+llength+1,rdp);
			memcpy(temp.key, treestack[top].key,pklen);
			for(j=0;j<merlen;j++) 
				temp.key[pklen-merlen+j] = temp.key[pklen-merlen+j] ^ nodestack.key[j];
			memcpy(temp.key+pklen, nodestack.key+merlen,pklen-merlen);
			for(j=0;j<sklen;j++) temp.key[j] = temp.key[j] ^ rdp[j];
			parse(xbyte, temp.key);
			set_Key(nodestack.indx/2,nodestack.height+llength+1);
			SWIFFT(xbyte,A,nodestack.key);
			nodestack.height++;
			nodestack.indx = nodestack.indx/2;
			top --;

			
		}
		top++;
		treestack[top] = nodestack;
	}

    /**Set public key in a file and read from the same file*/
	memcpy(MSSPK.key,treestack[top].key,pklen);
	pn(MSSPK.key);
    printf("\n Check : Adding public Key\n");
    FILE *fw, *fr;
    ssize_t result = 0;
    const char *public_key_filename = "publicKeyMSS.pub";
    unsigned char *public_key = malloc(pklen);
    unsigned char *public_key2 = malloc(pklen);
    
    memcpy(public_key, MSSPK.key,pklen);
    fw = fopen(public_key_filename, "w");

    if (fw == NULL)
       return -1;

    if (1 != fwrite(public_key,1,pklen, fw)) {
   /* Write failed */
        printf("\n Write failed fw = %d \n",fw);
        fclose(fw);
        free(public_key);
        
    }
	printf("\n Public_key Written in File \n");
    for(int i=0;i<pklen;i++)
    	printf("%hhu ",public_key[i]);

   fr = fopen(public_key_filename, "r");
    int nfread = fread(public_key2, 1, pklen, fr);
    printf("\n Public_key Reading from the file: %d\n",nfread);
    for(int i=0;i<pklen;i++)
        printf("%hhu ",public_key2[i]);
    fclose(fr);
    free(public_key2);


}


/** Generate all component keys of a KSN-OTS instance.
	seed_ctx : is a representation of a ChaCha key.
	idu8     : is the index of this OTS instance in the KSN-MSS scheme.
	sk       : is filled with the secret component keys.
 */
void generate_secret_key_OTS(ECRYPT_ctx *seed_ctx, u8 *idu8, sk_node *sk){
	int i;
	
	u8 key[sklen];
	u8 OTS_seed[seedlen];
	u8 component_seed[seedlen];

    //Index of a component key of the idu8^th OTS instance. Indices start at 1.
    //1024 bits long
	u8 component_id[sklen]={1,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 
				0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,
                   		0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 
				0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0};
	ECRYPT_ctx OTS_seed_ctx, component_seed_ctx;

    //OTS_seed = ChaCha_seed_ctx(idu8)
	ECRYPT_encrypt_bytes(seed_ctx,idu8,OTS_seed,seedlen);

    //Set up ChaCha context using OTS_seed as both nonce and iv
	ECRYPT_keysetup(&OTS_seed_ctx,OTS_seed,256,64);
	ECRYPT_ivsetup(&OTS_seed_ctx,OTS_seed);

    // Next two for loops compute all secret component keys for this OTS instance
    // The j^th secret component key of this instance = ChaCha_OTS_seed_ctx(j)
	for(i=0;i<255;i++){
		ECRYPT_encrypt_bytes(&OTS_seed_ctx,component_id,(sk+i)->key,sklen);
		component_id[0]=component_id[0]+1;
	}

    //Increment component_id from 254 to 255
	component_id[0]=0;
	component_id[1]=1;

    //Compute rest of seeds
	for(i=255;i<k2sn_t;i++){
		ECRYPT_encrypt_bytes(&OTS_seed_ctx,component_id,(sk+i)->key,sklen);
		component_id[0]=component_id[0]+1;
	}
	
}



/**
 * Computes public key of a KSN-OTS instance from the secret component keys and a SWIFFT key.
 * sk : is an array of secret keys.
 * A  : is the SWIFFT key.
 * pk : The public component keys are stored in pk.
 *
 */
void generate_public_key_OTS(sk_node *sk, node *pk, vec A[16][4]){
	int i;
	int xbyte[16][4];
	for(i=0;i<k2sn_t;i++){
		parse(xbyte, (sk+i)->key);
		SWIFFT(xbyte,A,(pk+i)->key);
	}
}


/**
 * Create L_i tree with exactly 262 component trees. Tree has 9 layers, where L0 is the bottom
 * layer and L8 is the root of the tree. L0 contains only 12 nodes on the left side which are
 * the first 12 hashed component keys. L1 contains 256 nodes. The first 6 nodes from the left
 * are the hashes of pairs of nodes from layer L0. The next 250 nodes in L1 are the remaining
 * 250 hashed component keys.
 *
 */
node create_L_tree(node *pk, u32 id){
	node 	internal_node[k2sn_t/2];
	sk_node	temp;
	int i,j,k,w,l1;

    //id < 2^h = 2^20 so this does not erase any bits. id_t = id*(2^9) so id_t < 2^29 always
	u32 id_t=id<<llength;
	int xbyte[16][4];
	u8 rdp[sklen];


    //Compute the first 6 nodes from the left of L1. These are computed from the first 12 hashed component keys
	for(i=0;i<6;i++){
		set_random_pad(id_t+i,0,rdp);

        //Merge y_2i and y_2i+1
		memcpy(temp.key, (pk+2*i)->key,pklen);
		for(j=0;j<merlen;j++) 
			temp.key[pklen-merlen+j] = temp.key[pklen-merlen+j] ^ (pk+2*i+1)->key[j];
		memcpy(temp.key+pklen, (pk+2*i+1)->key+merlen,pklen-merlen);

        //XOR randompad
		for(j=0;j<sklen;j++) temp.key[j] = temp.key[j] ^ rdp[j];
		parse(xbyte, temp.key);

        //Hash (Merge(y_2i, y_2i+1) XOR randompad)
		set_Key(id_t+i,0);
		SWIFFT(xbyte,A,(internal_node+i)->key);
	}


    //Compute the first 3 from the left nodes of L2. These are computed from the first 6 nodes nodes in L1
	id_t = id_t/2;
	for(i=0;i<3;i++){
		set_random_pad(id_t+i,1,rdp);
        //Merge y_i
		memcpy(temp.key, internal_node[2*i].key,pklen);
		for(j=0;j<merlen;j++) 
			temp.key[pklen-merlen+j] = temp.key[pklen-merlen+j] ^ internal_node[2*i+1].key[j];
		memcpy(temp.key+pklen, internal_node[2*i+1].key+merlen,pklen-merlen);
		for(j=0;j<sklen;j++) temp.key[j] = temp.key[j] ^ rdp[j];
		parse(xbyte, temp.key);
		set_Key(id_t+i,1);
		SWIFFT(xbyte,A,(internal_node+i)->key);
	}

    //Compute the remaining 125 nodes of L2. These are computed from the remaining 250 hashed component keys.
	k=3;
	for(i=6;i<131;i++){
		set_random_pad(id_t+i,1,rdp);
		memcpy(temp.key, (pk+2*i)->key,pklen);
		for(j=0;j<merlen;j++) 
			temp.key[pklen-merlen+j] = temp.key[pklen-merlen+j] ^ (pk+2*i+1)->key[j];
		memcpy(temp.key+pklen, (pk+2*i+1)->key+merlen,pklen-merlen);
		for(j=0;j<sklen;j++) temp.key[j] = temp.key[j] ^ rdp[j];
		parse(xbyte, temp.key);
		set_Key(id_t+i,1);
		SWIFFT(xbyte,A,(internal_node+k)->key);
		k++;
	}

    //Iteratively compute the remaining 6 layers of the L_i tree.
	w = 1 << (llength-3);
	l1 = 2;
	for(k=hlength+llength-2;k>hlength;k--){
		id_t = id_t/2;
		for(i=0;i<w;i++){
			set_random_pad(id_t+i,l1,rdp);
			memcpy(temp.key, internal_node[2*i].key,pklen);
			for(j=0;j<merlen;j++) 
				temp.key[pklen-merlen+j] = temp.key[pklen-merlen+j]^internal_node[2*i+1].key[j];
			memcpy(temp.key+pklen, internal_node[2*i+1].key+merlen,pklen-merlen);
			for(j=0;j<sklen;j++) temp.key[j] = temp.key[j] ^ rdp[j];
			parse(xbyte, temp.key);
			set_Key(id_t+i,l1);
			SWIFFT(xbyte,A,(internal_node+i)->key);
		}
		w = w>>1;
		l1++;
	}
	
	return internal_node[0];
}


/**
 * Generates signature from message ms using the id^th OTS instance
 */
void ksnmss_sign(u32 id, u8 *ms, ksnmss_sig *sig){
	int i,j,k,le;
	u32	id_t;
	u8 	idu8[seedlen]={0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0};
	sk_node sk[k2sn_t];
	node	pk[k2sn_t];
	u8 sksum[sklen*8];
	ECRYPT_ctx seed_ctx;
	rg_elm sum,temp_rg;
	u8 temp;
	int tempp;
	clock_t t2,t1=0;
	double time_taken;
	double cycles[1000],min;
	uint32 tau;
	uint32 maxh;
	uint32 eo;
	sk_node	temp2;
	int xbyte[16][4];
	u32 uindx;
	u8 rdp[sklen];

    //Generate all 262 secret component keys and their corresponding public component keys
	ECRYPT_keysetup(&seed_ctx,system_seed,256,64);
	ECRYPT_ivsetup(&seed_ctx,system_iv);
	id_t=id;
	idu8[0] = (u8)(id_t & 0xFF);	id_t = id_t >> 8;
	idu8[1] = (u8)(id_t & 0xFF);	id_t = id_t >> 8;
	idu8[2] = (u8)(id_t & 0xFF);	id_t = id_t >> 8;
	idu8[3] = (u8)(id_t & 0xFF);
	generate_secret_key_OTS(&seed_ctx, idu8, sk);
	set_Key(id,0);
	generate_public_key_OTS(sk, pk, A);

    //Generate subset of component keys based on message
	convert_u82u256(ms);
	cff();
	
	k=0;
    //Copy first public component key of the subset generated by cff() into sksum, bit by bit for some reason
	for(i=0;i<sklen;i++){
		temp=1;
		for(j=0;j<8;j++){
			sksum[k]=(u8)(((sk[component_key[0]].key[i])&temp)>>j);
			k++; temp=temp<<1;
		}
	}

    //Modular add rest of subset of component keys to sksum, bit by bit
	for(le=1;le<tb2;le++){
		k=0;
		for(i=0;i<sklen;i++){
			temp=1;
			for(j=0;j<8;j++){
				sksum[k]=sksum[k]+(u8)(((sk[component_key[le]].key[i])&temp)>>j);
				k++; temp=temp<<1;
			}
		}
	}

    //Fill in values of signature
	sig->id = id;
	memcpy(sig->message,ms,k2sn_msglen);
	memcpy(sig->sksum,sksum,sklen*8);   //sum subset of secret component keys
	memcpy(sig->pk,pk,k2sn_t*pklen);    //all public component keys of this OTS instance
	memcpy(sig->auth,auth,hlength*pklen);   //authorization path which I guess was computed last time this message was called?

// TODO compute auth path of signature?
	if(id < usr){
		//1
        //If id is
		eo = id&1;
		if(eo==0) tau = 0;
		else {	id_t = id+1;
			tau = 0;
			while((id_t&1)==0){
				tau++;
				id_t = id_t>>1;
			}
		}

		//2
		id_t = id>>(tau+1);
		if(((id_t&1)==0) && (tau<(hlength-1)))
			keep[tau]=auth[tau];

		//3
		if(eo==0)
			auth[0]=create_L_tree(pk,id);
	
		//4
		//if(eo==1){
		if(tau>0){
			id_t = id>>tau;
			set_random_pad(id_t,tau+llength,rdp);
			memcpy(temp2.key, auth[tau-1].key,pklen);
			for(j=0;j<merlen;j++) 
				temp2.key[pklen-merlen+j] = temp2.key[pklen-merlen+j]^keep[tau-1].key[j];
				memcpy(temp2.key+pklen, keep[tau-1].key+merlen,pklen-merlen);
				for(j=0;j<sklen;j++) temp2.key[j] = temp2.key[j] ^ rdp[j];
				parse(xbyte, temp2.key);
				set_Key(id_t,tau+llength);
				SWIFFT(xbyte,A,auth[tau].key);
			for(i=0;i<tau;i++){
				if(i<hlength-2){ memcpy(auth[i].key, (instance[i].v).key,pklen);
				}
				else if(i==(hlength-2)) memcpy(auth[i].key, retain.key,pklen);
			}
			for(i=0;i<tau;i++){
				tempp = id+1+3*(1<<i);
				if(tempp < usr){
					instance[i].finalized = 0;
					instance[i].startleaf = tempp;
					if(instance[i].top==-1)
						instance[i].lowheight = 0;
				}
			}

		}
		
		int minh,minindx,update=0;
		node 	leaf;
		mssnode	nodestack;
		for(i=0;i< updateiter;i++){
			minh=infy; //minindx=infy;
			for(j=0;j<hlength-2;j++){
				if((instance[j].lowheight!=infy) && (instance[j].finalized!=1)){
					if (minh>instance[j].lowheight){
						minh = instance[j].lowheight;
						minindx = j;
					}
				}
			}
			if(minh<infy){
				id_t=instance[minindx].startleaf;
				idu8[0] = (u8)(id_t & 0xFF);	id_t = id_t >> 8;
				idu8[1] = (u8)(id_t & 0xFF);	id_t = id_t >> 8;
				idu8[2] = (u8)(id_t & 0xFF);	id_t = id_t >> 8;
				idu8[3] = (u8)(id_t & 0xFF);
				ECRYPT_keysetup(&seed_ctx,system_seed,256,64);
				ECRYPT_ivsetup(&seed_ctx,system_iv);
				generate_secret_key_OTS(&seed_ctx, idu8, sk);
				set_Key(instance[minindx].startleaf,0);
				generate_public_key_OTS(sk, pk,A);
				leaf = create_L_tree(pk,instance[minindx].startleaf);

//set_Key(id_t,tau+l);

				if(minindx==0){
					memcpy((instance[minindx].v).key, leaf.key,pklen);
					instance[minindx].finalized = 1;
					instance[minindx].lowheight = infy;
				}
				else if(instance[minindx].top==-1){
					instance[minindx].top++;
					memcpy((instance[minindx].treestack[0]).key,leaf.key,pklen);
					(instance[minindx].treestack[0]).indx=instance[minindx].startleaf;
					(instance[minindx].treestack[0]).height=0;
					instance[minindx].startleaf = instance[minindx].startleaf+1;
				}
				else{
					memcpy(nodestack.key,leaf.key,pklen);
					nodestack.height = 0;
					nodestack.indx = instance[minindx].startleaf;
					while((instance[minindx].top!=-1) && (nodestack.height==(instance[minindx].treestack[instance[minindx].top]).height)){
						memcpy(temp2.key, (instance[minindx].treestack[instance[minindx].top]).key,pklen);
						for(k=0;k<merlen;k++) 
							temp2.key[pklen-merlen+k] = temp2.key[pklen-merlen+k]^nodestack.key[k];
						memcpy(temp2.key+pklen, nodestack.key+merlen,pklen-merlen);
						set_random_pad(nodestack.indx/2,nodestack.height+1+llength,rdp);
						for(k=0;k<sklen;k++) temp2.key[k] = temp2.key[k] ^ rdp[k];
						parse(xbyte, temp2.key);
						set_Key(nodestack.indx/2,nodestack.height+1+llength);
						SWIFFT(xbyte,A,nodestack.key);
						nodestack.height++;	
						instance[minindx].top--;
						nodestack.indx=nodestack.indx/2;
					}
					if(nodestack.height == minindx){
						memcpy((instance[minindx].v).key,nodestack.key,pklen);
						instance[minindx].finalized = 1;
						instance[minindx].lowheight = infy;
						instance[minindx].top = -1;
					}else{
						instance[minindx].top++;
						//memcpy((instance[minindx].treestack[instance[minindx].top]).key,nodestack.key,pklen);
						//(instance[minindx].treestack[instance[minindx].top]).height = nodestack.height;
						//(instance[minindx].treestack[instance[minindx].top]).indx = nodestack.indx;		
						(instance[minindx].treestack[instance[minindx].top]) = nodestack;
						instance[minindx].startleaf = instance[minindx].startleaf+1;
						
						if(instance[minindx].top==0)
							instance[minindx].lowheight = nodestack.height;
					}
				}
			}else break;
		}
	}
}


/**
 * Returns 0 on success and different error values otherwise.
 */
int ksnmss_verify(u32 id, u8 *ms, ksnmss_sig *sig){
	int 	i,j,k,le;
	u32	id_t;
	int 	x[16][64];
	u8 	idu8[seedlen];
	sk_node sk[k2sn_t];
	node	pk[k2sn_t];
	u32 	pksum[rglen];
	ECRYPT_ctx seed_ctx;
	rg_elm 	sum,temp;
	sk_node	temp_node;
	int xbyte[16][4];
	u32    verified;
	int tempp;
	u8 rdp[sklen];
	clock_t t2,t1=0;



	//When sksum is the sum of the secret key components associated with B_mes

	//if sksum[i] >131
    //Treating sksum as a degree 1023 polynomial, check that no coefficient are larger than half the number of secret component keys
	for(i=0;i<1024;i++){
		if(sig->sksum[i]>131) return 3;
	}

    //Compute subset of component keys based on message
	convert_u82u256(ms);
	cff();

    //Hash secret keys with SWIFFT
	for(i=0;i<16;i++){
		for(j=0;j<64;j++) x[i][j] = sig->sksum[i*64+j];
	}
	set_Key(id,0);
	gSWIFFT(x,A,pksum);

    //Converts public component key which is a compressed ring elements into a ring element
	convert_ring((sig->pk[component_key[0]]).key,&sum);

    //Converts rest of public component keys into ring elements and adds them together, but not modular addition, just addition
	for(le=1;le<tb2;le++){
		convert_ring((sig->pk[component_key[le]]).key,&temp);
		for(i=0;i<rglen;i++){
			sum.key[i] = sum.key[i]+temp.key[i];
		}
	}

    //Modular addition
	for(i=0;i<rglen;i++){
		sum.key[i] = sum.key[i]%257;
	}


    //Checks that checksum in signature matches sum of public keys corresponding to message
	verified = 0;
	for(i=0;i<rglen;i++) verified = verified + (pksum[i]-sum.key[i]);
	//printf("%d\n",verified);
	if (verified != 0) return 2;

    //Compute L tree out of OTS component keys from signature
	node present,left,right;
	present= create_L_tree(sig->pk,id);

    //Use auth path from signature to compute the root node of a merkle tree
	for(i=0;i<hlength;i++){
		if(id%2==0){
			left = present; right=sig->auth[i];
		}
		else{
			left = sig->auth[i]; right=present;
		}
		memcpy(temp_node.key, left.key,pklen);
		for(j=0;j<merlen;j++) 
			temp_node.key[pklen-merlen+j] = temp_node.key[pklen-merlen+j] ^ right.key[j];
		memcpy(temp_node.key+pklen, right.key+merlen,pklen-merlen);
		set_random_pad(id/2,i+llength+1,rdp);
		for(j=0;j<sklen;j++) temp_node.key[j] = temp_node.key[j] ^ rdp[j];
		parse(xbyte, temp_node.key);
		set_Key(id/2,i+llength+1);
		SWIFFT(xbyte,A,present.key);
		id = id/2;
	}

    //Check that root node of computed merkle tree is the public key
	verified = 0;
	for(i=0;i<pklen;i++){
		//verified = verified + (MSS[mmsize-1].key[i]-present.key[i]);
		verified = verified + (MSSPK.key[i]-present.key[i]);
	}
	
	if (verified == 0) return 0; //verified success
	else return 1;

}


/**
 * Convert vector of 72 bytes to an element in the ring Z^64_257
 * Treats rg8 as vector of 9 bit numbers and stores each element in the first 9 bits of a 32 bit
 * element of a ring vector.
 */
void convert_ring(u8 *rg8, rg_elm *a){
	int i;
	for(i=0;i<8;i++){
		a->key[8*i+0] = rg8[9*i+0]; //Put first 8 bits of rg8 into first 8 bits of a.key[0]
		a->key[8*i+0] = a->key[8*i+0] | ((u32)(rg8[9*i+1]&0x1)<<8); //Put 0th bit of rg8 into 9th bit of a.key[0]
		
		a->key[8*i+1] = ((u32)(rg8[9*i+1])>>1); //Put 10th to 16th bits of rg8 into first 7 bits of a.key[1]
		a->key[8*i+1] = a->key[8*i+1]|((u32)(rg8[9*i+2]&0x3)<<7); //Puts next two bits in the 8th and 9th bits of a.key[1]

		a->key[8*i+2] = ((u32)(rg8[9*i+2])>>2);
		a->key[8*i+2] = a->key[8*i+2]|((u32)(rg8[9*i+3]&0x7)<<6);

		a->key[8*i+3] = ((u32)(rg8[9*i+3])>>3);
		a->key[8*i+3] = a->key[8*i+3]|((u32)(rg8[9*i+4]&0xF)<<5);

		a->key[8*i+4] = ((u32)(rg8[9*i+4])>>4);
		a->key[8*i+4] = a->key[8*i+4]|((u32)(rg8[9*i+5]&0x1F)<<4);

		a->key[8*i+5] = ((u32)(rg8[9*i+5])>>5);
		a->key[8*i+5] = a->key[8*i+5]|((u32)(rg8[9*i+6]&0x3F)<<3);

		a->key[8*i+6] = ((u32)(rg8[9*i+6])>>6);
		a->key[8*i+6] = a->key[8*i+6]|((u32)(rg8[9*i+7]&0x7F)<<2);

		a->key[8*i+7] = ((u32)(rg8[9*i+7])>>7);
		a->key[8*i+7] = a->key[8*i+7]|((u32)rg8[9*i+8]<<1);
	}
}



/**
 * Prints representation of node to standard output.
 */
void pn(node *r){
	printf("\n");
	for(int i=0;i<pklen;i++)
		printf("%hhu ",r->key[i]);
	printf("\n");
}


/**
 * Sets randompad as ChaCha_randompad_ctx((2^512)*height + indx) where randompad_ctx is a
 * ChaCha context generated using randompad_seed and randompad_iv.
 */
void set_random_pad(u32 indx, u32 height, u8 randpad[sklen]){

    //Set up ChaCha key using randompad seed and iv
	ECRYPT_ctx seed_ctx;
	ECRYPT_keysetup(&seed_ctx,randompad_seed,256,64);
	ECRYPT_ivsetup(&seed_ctx,randompad_iv);
	u8 ina[sklen]={0};


	ina[0] = indx & 255; indx = indx >>8;
	ina[1] = indx & 255; indx = indx >>8;
	ina[2] = indx & 255; indx = indx >>8;
	ina[3] = indx & 255;

	ina[64] = height;

	ECRYPT_encrypt_bytes(&seed_ctx,ina,randpad,128);
	
}

