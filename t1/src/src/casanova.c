#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdio.h>
#include <sys/un.h>
#include <unistd.h>
#include <pthread.h>
#include <semaphore.h>
#include <sys/ioctl.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/engine.h>

#include "casanova.h"
#include "locking/locking.h"
#include "hash/hash.h"

/* as entradas são pequenas, o resultado da criptografia terá
   sempre 16 bytes */
#define CRYPTEDSIZE  16

#define PUT_THREADS 4
#define GET_THREADS 8

/* Chave utilizada, obviamente não é seguro coloca-la aqui em
   plain text, mas isso é apenas um toy */
unsigned char *key = (unsigned char *)"01234567890123456789012345678901";
inline int encrypt(EVP_CIPHER_CTX *, unsigned char *, int , unsigned char *);
inline int decrypt(EVP_CIPHER_CTX *, unsigned char *, int , unsigned char *);

void handleErrors(void)
{
  ERR_print_errors_fp(stderr);
}


void get_entries();
void put_entries();

void store_mult();
void retrieve_mult();


FILE *fp;

sem_t sem_mutex_crypt;
sem_t sem_mutex_hash;
sem_t sem_rw;

// semafaros de sincronizacao de leitura e escrita
sem_t sem_put_ready;
sem_t sem_get_ready;

// semafaro que diz se a thread de [id] tem servico para executar
sem_t sem_put_service[PUT_THREADS];
sem_t sem_get_service[GET_THREADS];

sem_t sem_wakeup_get; //Semafaro que verifica se posso acordar as threads
sem_t sem_get_wating[GET_THREADS]; //semafaro que segura a thread se ela estiver tentando ler um id que não esta diponivel ainda

//Listas de threads
pthread_t put_threads[PUT_THREADS]; 
pthread_t get_threads[GET_THREADS];

// Determina se a thread de [id] esta trabalhando ou ja finalizou
int put_working[PUT_THREADS];
int get_working[GET_THREADS];

// Qual o tamanho da mensagem no buffer da thread de escrita de [id]
int get_mavail[GET_THREADS];
int put_mavail[PUT_THREADS];

char put_buffer[PUT_THREADS][PUT_MESSAGE_SIZE*680]; // Buffer da thread [id]
char get_buffer[GET_THREADS][GET_MESSAGE_SIZE*546]; // Buffer da thread de leitura

long long int put_actual[PUT_THREADS]; // enor id do bloco que esta sendo escrito, quando o bloco é escrito passa a ser o ultimo id do bloco
int get_waiting[GET_THREADS]; // Diz se a thread esta espearndo no semafaro, provavelmente poderiamos ler o semafaro ou sempre dar post

// sem_t sem_teste;

th_tabelahash th;

EVP_CIPHER_CTX *ctxge, *ctxgd;

int main(int argc, char *argv[]) {

    //init Hash//
    th = th_init();
    /* inicialização */
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
    OPENSSL_config(NULL);

	sem_init(&sem_mutex_hash, 0, 1);
	sem_init(&sem_mutex_crypt, 0, 1);
	sem_init(&sem_rw, 0, 1);
	// sem_init(&sem_teste, 0, 1);


    pthread_t thread1, thread2;
	thread_setup();

    /* Cria um thread para a entrada e outra para a saída */
	pthread_create (&thread1, NULL, (void *) &put_entries, (void *) 0);
	pthread_create (&thread2, NULL, (void *) &get_entries, (void *) 0);

    /* espero a morte das threads */
	pthread_join(thread1, NULL);
	pthread_join(thread2, NULL);

    fprintf(stdout, "Cleaning up\n");
    /* limpeza geral, hash tabela, semáforos e biblioteca de criptografia */
    thread_cleanup();
    th_destroy(th);

	sem_destroy(&sem_mutex_hash);
	sem_destroy(&sem_mutex_crypt);
	sem_destroy(&sem_rw);

    FIPS_mode_set(0);
	ENGINE_cleanup();
    CONF_modules_unload(1);
    EVP_CIPHER_CTX_free(ctxge);
    EVP_CIPHER_CTX_free(ctxgd);
  	EVP_cleanup();
    CRYPTO_cleanup_all_ex_data();
    ERR_remove_state(0);
  	ERR_free_strings();

	return 0;
}


inline void store(char* buffer, EVP_CIPHER_CTX * ctxe)
{
    unsigned char telefone_crypt[16];
    unsigned char nome_crypt[16];
    
    encrypt( ctxe, (unsigned char*) buffer, NOME_SIZE, nome_crypt );
    encrypt( ctxe, (unsigned char*) (buffer+NOME_SIZE), FONE_SIZE, telefone_crypt );
    
    th_insert(nome_crypt,telefone_crypt,th);
}

void put_entries()
{
    int server_sockfd, client_sockfd, i, ac;
    struct sockaddr_un server_address;
    struct sockaddr_un client_address;
	socklen_t addr_size;

	int count=0, bytesrw = 0, bytesrw_aux = 0;
	int read_ret, read_total, m_avail, m_avail_now;


    int put_pronta = 0;
    int *k;
	sem_init(&sem_put_ready, 0, 0);
    for (i = 0; i < PUT_THREADS; i++){
        k = (int *) malloc (sizeof(int));
        *k = i;
        sem_init(&sem_put_service[i], 0, 0);
        sem_init(&sem_wakeup_get, 0, 1);
        put_working[i] = 0;
        put_actual[i] = 0xffffffff;
        put_buffer[i][PUT_MESSAGE_SIZE] ='\0';
        pthread_create(&put_threads[i], NULL, (void*) &store_mult, (void *) k);
    }

    put_actual[0] = -1;

    /* inicializa SOCK_STREAM */
    unlink(SOCK_PUT_PATH);
    server_sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
    server_address.sun_family = AF_UNIX;
    strcpy(server_address.sun_path, SOCK_PUT_PATH);
    bind(server_sockfd, (struct sockaddr *)&server_address, sizeof(server_address));

	/* aguarda conexão */
	listen(server_sockfd, 5);

	fprintf(stderr, "PUT WAITTING\n");
	addr_size=sizeof(client_address);
    client_sockfd = accept(server_sockfd, (struct sockaddr *)&client_address, &addr_size);
	fprintf(stderr, "PUT CONNECTED\n");


	do {
        //espera alguma thread estar pronta
        sem_wait(&sem_put_ready);
        //descobre qual esta pronta, seta put_pronta
        for(i = 0; i< PUT_THREADS; i++){
            if(put_working[i] == 1){
                put_pronta = i;
                //fprintf(stderr,"%d ", i);
                break;
            }
        }

        /* le o número de mensagens escolhido */
        read_total=0;
        m_avail = 0;

        /* numero de mensagens inteiras no buffer */
	    ioctl(client_sockfd, FIONREAD, &bytesrw);
        m_avail_now = bytesrw / PUT_MESSAGE_SIZE;
        if (m_avail_now == 0 ) m_avail_now = 1;
        if (m_avail_now > 680 ){m_avail_now = 680;} 
        // fprintf(stderr,"%d ",m_avail_now);

        m_avail = m_avail_now;

        /* le o número de mensagens escolhido */
        read_total=0;

	    do {
            read_ret=read(client_sockfd, put_buffer[put_pronta], PUT_MESSAGE_SIZE*m_avail-read_total);
            read_total+=read_ret;
        } while (read_total < PUT_MESSAGE_SIZE*m_avail && read_ret > 0 );

        /* verificamos se sobrou algum dado na fila de writers, não precisa um mutex, já
               que essa é a única thread acessando esses dados */
	    ioctl(client_sockfd, FIONREAD, &bytesrw);
	    /* se na anterior era 0, não tinha travado o leitor */

        if ( bytesrw_aux == 0 && bytesrw > 0 )
		sem_wait (&sem_rw);

        /* se acabou, posso destrancar o leitor */
	    if ( bytesrw_aux !=0 && bytesrw == 0 )
	        sem_post (&sem_rw);
	    bytesrw_aux = bytesrw;

        if (read_ret <=0)
           m_avail=0;
        put_mavail[put_pronta] = m_avail;

        if(read_ret > 0){
            put_working[put_pronta] = 0;
            sem_post(&sem_put_service[put_pronta]);
        }

	    count+=m_avail;
	} while (read_ret > 0) ;

    //espera todas as threads terminarem
    i = 0;
    ac = 0;
	sem_destroy(&sem_put_ready);
    while (1){
        if(ac == PUT_THREADS)
            break;
        if(put_working[i] == 1){
            put_mavail[i] = -1;
            sem_post(&sem_put_service[i]);
            pthread_join(put_threads[i], NULL);
            sem_destroy(&sem_put_service[i]);
            fprintf(stderr,"Thread %d: Acabou\n", i);
            ac++;
        }
        i++;
        if(i == PUT_THREADS)
            i = 0;
    }
    sem_wait(&sem_wakeup_get);
    for(int i=0; i < PUT_THREADS; i++)
        put_actual[i] = 0xffffffff;
    for(int i=0; i < GET_THREADS; i++)
        sem_post(&sem_get_wating[i]);
    close(client_sockfd);
	fprintf(stderr, "PUT EXITED, %d MESSAGES RECEIVED \n", count );
}

void store_mult(void *id){
    EVP_CIPHER_CTX *ctxe;
    if(!(ctxe = EVP_CIPHER_CTX_new())) handleErrors();
    int my_id = *((int *) id);
    free(id);
    int n;
    put_working[my_id] = 1;
    sem_post(&sem_put_ready);

    while(1){
       sem_wait(&sem_put_service[my_id]);

       if(put_mavail[my_id] == -1)
           break;

       //consome
       for (n =0; n < put_mavail[my_id]; n++){
           store(put_buffer[my_id]+ID_SIZE+n*PUT_MESSAGE_SIZE,ctxe);
       }
       char * last_insert = put_buffer[my_id]+(n-1)*PUT_MESSAGE_SIZE;
       last_insert[ID_SIZE] = '\0';

       put_actual[my_id] = strtol(last_insert, NULL, 16); //preciso de um semaforo aqui?Acho que nao
       //ACORDA THREADS DE GET
       
       //Threads de leitura que possuem id maior que alguma thread que esta escrevendo ficam esperando serem acordadas por um semaforo
       //Aqui acordamos as threads, provavelmmente nao precisamos desse semaforo, mas apenas para garantir
       sem_wait(&sem_wakeup_get);
       for(int i =0; i < GET_THREADS; i++){
           if(get_waiting[i])
               sem_post(&sem_get_wating[i]);
       }
       sem_post(&sem_wakeup_get);

       put_working[my_id] = 1;
       sem_post(&sem_put_ready);

    }
    put_working[my_id] = -1;
    EVP_CIPHER_CTX_free(ctxe);
}

inline void retrieve(char* buffer, FILE *fp, EVP_CIPHER_CTX * ctxe, EVP_CIPHER_CTX * ctxde)
{
    int   telefoneint;
    unsigned char *telefonecrypt;
    unsigned char telefonedecrypt[FONE_SIZE+1];
    unsigned char nome_crypt[CRYPTEDSIZE+1];

    telefonedecrypt[FONE_SIZE] = '\0';
    nome_crypt[CRYPTEDSIZE] = '\0';

    /* criptografa nome para fazer a busca */
    encrypt( ctxde, (unsigned char*) buffer, NOME_SIZE, nome_crypt );
    
    telefonecrypt = th_get(nome_crypt, th);
    if ( telefonecrypt == NULL)
    {   
        //Nunca deve acontecer
        sem_post(&sem_mutex_hash);
        fprintf(stderr, "NAO ENCONTRADO\n");
        return;
    }
    decrypt(ctxe, telefonecrypt, CRYPTEDSIZE, telefonedecrypt);
    telefonedecrypt[FONE_SIZE] = '\0';
    /* se quiser ver as entradas descomente
    fprintf(stdout, "%.15s %s\n", buffer, telefonedecrypt); */
    telefoneint = atoi((char*) telefonedecrypt);
    fwrite( (void*) &telefoneint, sizeof(int), 1, fp);
}
void retrieve_mult(void *id){
    EVP_CIPHER_CTX *ctxe, *ctxde;
    if(!(ctxe = EVP_CIPHER_CTX_new())) handleErrors();
    if(!(ctxde = EVP_CIPHER_CTX_new())) handleErrors();

    int my_id = *((int *) id);
    int i;
    free(id);
    int n;
    get_working[my_id] = 1;
    sem_post(&sem_get_ready);

    int existe_menor;
    char *ptr;
    long long int actual_id;

    while(1){
       sem_wait(&sem_get_service
[my_id]);

       if(get_mavail[my_id] == -1)
           break;

       //consome
       for (n =0; n < get_mavail[my_id]; n++){
           ptr = ((char*)&(get_buffer[my_id]))+n*GET_MESSAGE_SIZE+ID_SIZE;
           actual_id = strtol(get_buffer[my_id]+n*GET_MESSAGE_SIZE,&ptr, 16);
           //fprintf(stdout,"%.8s %lli\n", get_buffer[my_id]+n*GET_MESSAGE_SIZE,actual_id);
           
           //procura se esta sendo escrito bloco com id menor do que minha leitura
           //Forma mais burra de executar mas executa rapido e consome pouca memoria
           do{
               existe_menor = 0;
               for (i = 0; i < PUT_THREADS; i++){
                   if (put_actual[i] != -1 && actual_id > put_actual[i]){
                       get_waiting[my_id] = 1;
                       sem_wait(&sem_get_wating[my_id]);
                       get_waiting[my_id] = 0;
                       existe_menor=1;
                   }
               }
           }while(existe_menor==1);
           retrieve(get_buffer[my_id]+ID_SIZE+n*GET_MESSAGE_SIZE,fp,ctxe,ctxde);
       }

       get_working[my_id] = 1;
       sem_post(&sem_get_ready);

    }
    get_working[my_id] = -1;
    EVP_CIPHER_CTX_free(ctxe);
    EVP_CIPHER_CTX_free(ctxde);
}

void get_entries()
{
    int server_sockfd, client_sockfd, i, ac;
    struct sockaddr_un server_address;
    struct sockaddr_un client_address;
	socklen_t addr_size;

	int count=0, read_ret, read_total, m_avail, bytesrw;

    int get_pronta = 0;
    int *k;
    sem_init(&sem_get_ready, 0, 0);
    for (i = 0; i < GET_THREADS; i++){
        k = (int *) malloc (sizeof(int));
        *k = i;
        sem_init(&sem_get_service
[i], 0, 0);
        sem_init(&sem_get_wating[i], 0, 0);
        get_working[i] = 0;
        get_waiting[i]=0;
        get_buffer[i][GET_MESSAGE_SIZE] ='\0';

        pthread_create(&get_threads[i], NULL, (void*) &retrieve_mult, (void *) k);
    }

	/* inicializa SOCK_STREAM */
    unlink(SOCK_GET_PATH);
    server_sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
    server_address.sun_family = AF_UNIX;
    strcpy(server_address.sun_path, SOCK_GET_PATH);
    bind(server_sockfd, (struct sockaddr *)&server_address, sizeof(server_address));
    listen(server_sockfd, 5);

	fprintf(stderr, "GET WAITTING\n");
	addr_size=sizeof(client_address);
    client_sockfd = accept(server_sockfd, (struct sockaddr *)&client_address, &addr_size);
	fprintf(stderr, "GET CONNECTED\n");
	fp=fopen(OUTPUTFILE, "w+");

	if (fp==NULL)
	{
		perror("OPEN:");
		exit(1);
	}

	do {
        sem_wait(&sem_get_ready);
        //descobre qual esta pronta, seta put_pronta
        for(i = 0; i< GET_THREADS; i++){
            if(get_working[i] == 1){
                get_pronta = i;
                //fprintf(stderr,"%d ", i);
                break;
            }
        }
        /* se tem writers, ele fica preso no sem_rw, liberado logo em seguida
           pois é só uma sincronização com a thread escritora e não uma região
           de exclusão mútua */
		sem_wait (&sem_rw);
		sem_post (&sem_rw);
        /* vejo quantidade de bytes no buffer */
        ioctl(client_sockfd, FIONREAD, &bytesrw);

        /* numero de mensagens inteiras no buffer */
        m_avail = bytesrw / GET_MESSAGE_SIZE;
        if (m_avail == 0 ) m_avail = 1;
        if (m_avail > 273 ) m_avail = 273;

        read_total=0;
        do {
            read_ret=read(client_sockfd, get_buffer[get_pronta], GET_MESSAGE_SIZE*m_avail-read_total);
            read_total+=read_ret;
        } while (read_total < GET_MESSAGE_SIZE*m_avail && read_ret > 0 );

        if (read_ret <=0)
           m_avail=0;

        //for (n=0;n<m_avail;n++)
        //    retrieve( buffer+n*GET_MESSAGE_SIZE,fp);
        get_mavail[get_pronta] = m_avail;

        if(read_ret > 0){
            get_working[get_pronta] = 0;
            sem_post(&sem_get_service
[get_pronta]);
        }
	    count+=m_avail;

	} while (read_ret > 0 );
    ac = 0;
    i = 0;
    while (1){
        if(ac == GET_THREADS)
            break;
        if(get_working[i] == 1){
            get_mavail[i] = -1;
            sem_post(&sem_get_service
[i]);
            pthread_join(get_threads[i], NULL);
            sem_destroy(&sem_get_service
[i]);
            fprintf(stderr,"Thread %d: Acabou\n", i);
            ac++;
        }
        i++;
        if(i == GET_THREADS)
            i = 0;
    }

    close(client_sockfd);
	fclose(fp);
    i = 0;
    ac = 0;
    sem_destroy(&sem_get_ready);
	fprintf(stderr, "GET EXITED, %d MESSAGES RECEIVED\n", count);
}


/* seguem as funções de criptografia. Eu estou usando elas no sabor não
   threadsafe, por isso o mutex. Na versão paralela é de se cogitar o
   uso thread safe desta mesma biblioteca */
int encrypt(EVP_CIPHER_CTX * ctxe, unsigned char *plaintext, int plaintext_len, unsigned char *ciphertext)
{

    int len;
    int ciphertext_len;

    if(1 != EVP_EncryptInit_ex(ctxe, EVP_aes_256_ecb(), NULL, key, NULL)) handleErrors();
    //  EVP_CIPHER_CTX_set_padding(ctxe, 1);
    if(1 != EVP_EncryptUpdate(ctxe, ciphertext, &len, plaintext, plaintext_len))
        handleErrors();
    ciphertext_len = len;
    if(1 != EVP_EncryptFinal_ex(ctxe, ciphertext + len, &len))
        handleErrors();
    ciphertext_len += len;

    return ciphertext_len;
}

int decrypt(EVP_CIPHER_CTX * ctxd, unsigned char *ciphertext, int ciphertext_len, unsigned char *plaintext)
{
    int plaintext_len, len;

    if(1 != EVP_DecryptInit_ex(ctxd, EVP_aes_256_ecb(), NULL, key, NULL))
        handleErrors();

    EVP_CIPHER_CTX_set_padding(ctxd, 0);

    if(1 != EVP_DecryptUpdate(ctxd, plaintext, &len, ciphertext, ciphertext_len))
    {
        BIO_dump_fp (stdout, (const char *)ciphertext, ciphertext_len);
        handleErrors();
    }
    plaintext_len = len;
    if(1 != EVP_DecryptFinal_ex(ctxd, plaintext + len, &len))
    {
        BIO_dump_fp (stdout, (const char *)ciphertext, ciphertext_len);
        handleErrors();
    }
        plaintext_len += len;

    return plaintext_len;
}



