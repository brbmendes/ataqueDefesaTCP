///// https://www.onlinegdb.com/online_c_compiler (To test online)
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h> // *POSIX* Para o getopt() original
#include <ctype.h>
#include "../headers/functions.h"

#define TCP_CONNECT "TCP Connect"
#define TCP_HALF_OPENING "TCP Half-Opening"
#define STEALTH_SCAN "Stealth Scan or TCP FIN"
#define SYN_ACK "SYN/ACK"


int main(int argc, char **argv) {
    int opt ;

    /*  Variables to store options arguments. */
    char *start_port=NULL, *end_port=NULL, *attack=NULL, *attempts=NULL, *source=NULL, *dest=NULL ;
	int int_start_port, int_end_port, int_attempts;
    int retAlp = 1;
	int retDig = 1;
    /* Call Help from program. */
    if ( argc < 2 ) show_help(argv[0]) ;

    /* getopt() Returns the character of an option at each 
	* i	teration and -1 to mark the end of the process. */
    while( (opt = getopt(argc, argv, "hi:f:a:t:s:d:")) > 0 ) {
        switch ( opt ) {
            case 'h': /* help */
                show_help(argv[0]) ;
                break ;
            case 'i': /* opção -i initial_port*/
				retAlp = check_alphabets(optarg, "Invalid port");
				if(retAlp < 0) return retAlp;
                start_port = optarg ;
                int_start_port = atoi (start_port);
                break ;
            case 'f': /* opção -e final_port*/
				retAlp = check_alphabets(optarg, "Invalid port");
				if(retAlp < 0) return retAlp;
                end_port = optarg ;
                int_end_port = atoi (end_port);
                break ;
            case 'a': /* opção -a attack*/
                retDig = check_digits(optarg, "Invalid attack");
				if(retDig < 0) return retDig;
				convert_lower(optarg);
                if(strcmp(optarg, "connect") == 0){
                    attack = TCP_CONNECT;
                } else if(strcmp(optarg, "half") == 0){
                    attack = TCP_HALF_OPENING ;
                } else if(strcmp(optarg, "stealth") == 0){
                    attack = STEALTH_SCAN ;
                } else if(strcmp(optarg, "syn_ack") == 0){
                    attack = SYN_ACK ;
                } else {
                    fprintf(stderr, "\nInvalid attack: %s\n\n", optarg) ;
                    return -1 ;
                }
                break ;
            case 't': /* opção -t attempts*/
				retAlp = check_alphabets(optarg, "Invalid number of attepts");
				if(retAlp < 0) return retAlp;
                attempts = optarg ;
                int_attempts = atoi (attempts);
                break ;
            case 's': /* opção -s IPv6 source*/
                source = optarg ;
                break ;
            case 'd': /* opção -d IPv6 destination*/
                dest = optarg ;
                break ;
			default:
                //fprintf(stderr, "Invalid dsdsd: `%c'\n", optopt) ;
                return -1 ;
        }
    }

    /* Mostra os argumentos em excesso */
    if ( argv[optind] != NULL ) {
        int i ;

        puts("** Excess of arguments **") ;
        for(i=optind; argv[i] != NULL; i++) {
            fprintf(stderr,"-- %s\n", argv[i]) ;
        }
		return -1;
    }
	
	/* Mostra os dados na tela. */
    printf("\tInformations: \n\
            Port Range \t: %s, %s\n\
            Attack  \t: %s\n\
            Attempts \t: %s\n\
            Source \t: %s\n\
            Destination : %s\n", start_port, end_port, attack, attempts, source, dest) ;

    for(int i = 0 ; i < int_attempts ; i++){
        int status = system("./bin/ipv6_send");
    }
    
    return 0 ;
    
}
/* EOF */