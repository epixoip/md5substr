# md5substr

Multi-threaded SIMD program to generate collisions for truncated MD5 hashes,
e.g. substr(md5(pass), 0, 8)

This can also be used to generate "vanity" MD5 hashes

# Compile

`cc -o md5substr md5substr.c -march=native -O4 -funroll-loops -pthread`

# Usage

`./md5substr <target> <offset>`

 # Examples
 
 If the hash "bab3d011" was generated with substr(md5(pass), 0, 8),
 
 `./md5substr bab3d011 0`
 
 If the hash "deadbea7" was generated with substr(md5(pass), 16, 8), 
 
 `./md5substr deadbea7 16`
 
 
