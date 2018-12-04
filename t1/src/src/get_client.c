#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "casanova.h"

int main(void)
{
    int server_socketfd, x, len, tsleep;
    struct sockaddr_un remote;
    char buffer[N_MESSAGE][GET_MESSAGE_SIZE];
    char buffertelefone[N_MESSAGE][FONE_SIZE+1];
    char hex[ID_SIZE];

    int m, aux, repeat, sent_ret, sent_total;
    int completed=0;


    /* inicializaca geracao aleatoria de strings */ 
    for ( x=0; x<N_MESSAGE; x+=4)
    {
       memcpy(buffer[x]  , "00000001 Daen Targaryen ", GET_MESSAGE_SIZE);
       memcpy(buffer[x+1], "00000002 Sansa Stark    ", GET_MESSAGE_SIZE);
       memcpy(buffer[x+2], "00000003 Cersei Lannist ", GET_MESSAGE_SIZE);
       memcpy(buffer[x+3], "00000004 Margaery Tyrel ", GET_MESSAGE_SIZE);

       buffertelefone[x][FONE_SIZE]='\0';
       buffertelefone[x+1][FONE_SIZE]='\0';
       buffertelefone[x+2][FONE_SIZE]='\0';
       buffertelefone[x+3][FONE_SIZE]='\0';

       memcpy(buffertelefone[x],   "843120303", FONE_SIZE);
       memcpy(buffertelefone[x+1], "243520303", FONE_SIZE);
       memcpy(buffertelefone[x+2], "943120303", FONE_SIZE);
       memcpy(buffertelefone[x+3], "143140301", FONE_SIZE);

    }
    int charsetsize = sizeof(charset) - 1, pos, aleat;
    char letra; 

	
    /* criacao do socket e conexao */	
    if ((server_socketfd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) 
    {
        perror("socket");
        exit(1);
    }
    remote.sun_family = AF_UNIX;
    strcpy(remote.sun_path, SOCK_GET_PATH);
    len = strlen(remote.sun_path) + sizeof(remote.sun_family);
    

    while (connect(server_socketfd, (struct sockaddr *)&remote, len) == -1) 
    {
        perror("connect");
        usleep(100);
    }

    printf("WAITING \n");

    tsleep = 10000;
    for (x=0; x < DATASET_SIZE; x+=N_MESSAGE)
    {
 	for (aux=0;aux<10;aux++)
        {
       /* altera um caracter a cada iteraçao */
        	for (m=0;m<N_MESSAGE;m++)
        	{
                	aleat=rand();
                	letra = charset[aleat % charsetsize];
               		pos = aleat % NOME_SIZE;
                	if (letra == ' ') pos = NOME_SIZE/5 + aleat % (NOME_SIZE/3);
                	buffer[m][pos+ID_SIZE]=letra;
			buffertelefone[m][aleat % FONE_SIZE] =   (((int)'0')+aleat%10);
        	}

        }

        /* gerado os ID_S em hexa */
        for (m=0;m<N_MESSAGE;m++)
        {
                sprintf(hex, "%08X", (x+N_MESSAGE+m));
                memcpy(buffer[m], hex, ID_SIZE-1);
        }

	/* professor casanova escolhe aleatoriamente seus contatos */ 
	if ( (aleat % 5 == 0)  || completed>10)
	{
		/* um pequeno cochilo no inicio */	
		if ( aleat % 30 == 0 && completed < 20 )
			usleep (tsleep); 
		repeat = 0;
		do {
			/* envia mensagem */
			sent_total = 0;
	        	do {
	                	sent_ret=send(server_socketfd, buffer, GET_MESSAGE_SIZE*N_MESSAGE-sent_total, 0);
	                	sent_total+=sent_ret;
       		 	} while (sent_total < GET_MESSAGE_SIZE*N_MESSAGE && sent_ret > 0);

       		         /* se quiser ver as entradas, descomente 
        		for (m=0;m<N_MESSAGE;m++)
				fprintf(stderr, "%.24s %s\n", buffer[m], buffertelefone[m]);  */
        		if (sent_ret <=0 ) {
           			perror("send");
           			exit(1);
			}
			repeat++;
		}
		while ( aleat%10 == 0 && repeat < 20 );

       	}

	if (completed != x/(DATASET_SIZE/100))
	{
		printf("G %d\n", (int) x/(DATASET_SIZE/100));
		completed = x/(DATASET_SIZE/100);
	}

    }
    close(server_socketfd);
    return 0;
}

