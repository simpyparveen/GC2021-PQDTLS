# ReadySHA3

Updated : 19 Sep 2019, Simpy Parveen(simpy.parveen1@ucalgary.ca)

A simple implemenation of SHA3 hash function. SHA-3 uses the sponge construction,[12][23] in which data is "absorbed" into the sponge, then the result is "squeezed" out. 
In the absorbing phase, message blocks are XORed into a subset of the state, which is then transformed as a whole using a permutation function f. In the "squeeze" phase, output blocks are read from the same subset of the state, alternated with the state transformation function f. 
The size of the part of the state that is written and read is called the "rate" (denoted r), and the size of the part that is untouched by input/output is called the "capacity" (denoted c).
The capacity determines the security of the scheme. The maximum security level is half the capacity.

SHA-3 Spec: http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf

This implementation is intended for study of the algorithm, not for
production use.

The code works correctly on 64-bit little-endian platforms with gcc.
Like your Linux box. The main.c module contains self-tests for all
officially supported hash sizes.


// Inut : Secret key(256bits = 32 bytes)
//Output : Public Key (256 bits= 32 bytes)


#Run and Compile :
Below are the commands to run and compile the codes. Please make necessary changes in main() to make use of (i)

(i)
    gcc main.c sha3.c -o output
    ./output

Note : int main() is replaced for int main(int argc, char **argv)


(ii)
      make
      ./sha3test

OR 
just run makefile by using : make


#Application:
Using Sha3 Sha256 to create a key chain of 10 keys. starting with a random key and then using the output of the hash function which becomes input to the next hash function.

