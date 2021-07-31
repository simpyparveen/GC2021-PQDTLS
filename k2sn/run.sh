gcc -m64 -mavx2 -O3 -fomit-frame-pointer -funroll-all-loops main.c
./a.out > result.txt
