#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "casanova.h"

int main(void)
{
    int server_socketfd, x, m, aux, len;
    struct sockaddr_un remote;
    char buffer[N_MESSAGE][PUT_MESSAGE_SIZE];
    char hex[ID_SIZE];
    int completed=0,tsleep, sent_ret, sent_total;
    int charsetsize = sizeof(charset) - 1, pos, aleat;
    char letra; 


    hex[ID_SIZE-1]=0;

    /* inicializaca geracao aleatoria de strings */
    for ( x=0; x<N_MESSAGE; x+=4)
    {
       memcpy(buffer[x],   "00000001 Daen Targaryen 843120303",PUT_MESSAGE_SIZE);
       memcpy(buffer[x+1], "00000002 Sansa Stark    243520303",PUT_MESSAGE_SIZE);
       memcpy(buffer[x+2], "00000003 Cersei Lannist 943120303",PUT_MESSAGE_SIZE);
       memcpy(buffer[x+3], "00000004 Margaery Tyrel 143140301",PUT_MESSAGE_SIZE);
    }

    /* criacao do socket e conexao */
    if ((server_socketfd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
        perror("socket");
        exit(1);
    }
    remote.sun_family = AF_UNIX;
    strcpy(remote.sun_path, SOCK_PUT_PATH);
    len = strlen(remote.sun_path) + sizeof(remote.sun_family);

    while (connect(server_socketfd, (struct sockaddr *)&remote, len) == -1) {
        perror("connect");
	usleep(1000);
    }

    printf("PUT CONNECTED.\n");
    tsleep = 500;
    for (x=0;x<DATASET_SIZE;x+=N_MESSAGE )
    {
	/* aux é apenas para repetir o número de alterações para cada mensagem */
	for (aux=0;aux<10;aux++)
        {
		/* altera um caracter a cada iteraçao */
		for (m=0;m<N_MESSAGE;m++)
        	{
	        	aleat=rand();
        		letra = charset[aleat % charsetsize];
        		pos = aleat % NOME_SIZE;
        		if (letra == ' ') pos = NOME_SIZE/5 + aleat % (NOME_SIZE/3);
        		buffer[m][pos + ID_SIZE]=letra;
			buffer[m][NOME_SIZE+ID_SIZE+(aleat % FONE_SIZE)] =   (((int)'0')+aleat%10); 
                }
        }
	/* gerado os ID_S em hexa */
        for (m=0;m<N_MESSAGE;m++)
        {
		sprintf(hex, "%08X", (x+N_MESSAGE+m));
		memcpy(buffer[m], hex, ID_SIZE-1);
        }
	sent_total = 0;
	do {
		sent_ret=send(server_socketfd, buffer, PUT_MESSAGE_SIZE*N_MESSAGE-sent_total, 0);
		sent_total+=sent_ret;
        } while (sent_total < PUT_MESSAGE_SIZE*N_MESSAGE && sent_ret > 0);
        /* se quiser ver as mensagens, use isto: 
         for (m=0;m<N_MESSAGE;m++)
              fprintf(stderr, "%.9s%.15s%.9s\n", buffer[m], buffer[m]+ID_SIZE, buffer[m]+ID_SIZE+NOME_SIZE);
	*/
	if (sent_ret <=0 ) {
	   perror("send");
	   exit(1);
       	}

	if ( (completed >30 && x%(100-completed+1) <= 10 ) )
        {
        	usleep (tsleep);
	}
	if (completed != x/(DATASET_SIZE/100))
        {
                printf("P %d\n", (int) x/(DATASET_SIZE/100));
                completed = x/(DATASET_SIZE/100);
        }

    }
    printf("PUT ENVIADOS %d\n", x);
    close(server_socketfd);
    return 0;
}
