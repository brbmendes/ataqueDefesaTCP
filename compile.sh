gcc -o bin/attack sources/functions.c sources/attack.c headers/functions.h
gcc -o bin/ipv6_send sources/ipv6_ll.c
gcc -o bin/tcp_send sources/tcp6_ll.c
