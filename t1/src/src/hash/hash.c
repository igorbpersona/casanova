#include "hash.h"

// struct to free th memory
struct th_id{
    th_tabelahash th;
    int id;
};

void th_destroy_lines(void *);

int th_hash (unsigned char *);

pthread_t th_threads[HT_DESTROY_TH];

th_tabelahash th_init () {
    int i;
    th_tabelahash th;
    th = (th_tabelahash) malloc(sizeof(th_tabelahash_t));
    if (th == NULL) return NULL;
    th->count = 0;
    // create (size) bucks in heap
    th->b = (lista_t *) malloc(sizeof(lista_t ) * HT_MAX_SIZE);
    if (th->b == NULL) return NULL;
    for (i = 0; i < HT_MAX_SIZE; i++){
        lista_init(&(th->b[i]));
    }
    return th;
}

void th_insert (unsigned char *key, unsigned char *value, th_tabelahash th) {
    lista_insert(&(th->b[th_hash(key)]), key, value);
    th->count++;
}

unsigned char *th_get (unsigned char *key, th_tabelahash th) {
    int hash;
    unsigned char *crypted_tel;

    hash = th_hash(key);
    crypted_tel = lista_find(&(th->b[hash]), key);

    return crypted_tel;
}

int th_hash (unsigned char *key) {
    int hash = 0, i;
    for (i = 0; i < 16; i++){
        hash += key[i];
        hash += (hash << 10);
        hash ^= (hash >> 6);
    }
    hash += (hash << 3);
    hash ^= (hash >> 11);
    hash += (hash << 15);
    return th_map_int(hash);
}

void th_destroy_lines(void *th){
    struct th_id *tht = (struct th_id *) th;
    int i;
    for( i = tht->id; i < HT_MAX_SIZE; i+= HT_DESTROY_TH)
        lista_destroy(&(tht->th->b[i]));

}

void th_destroy (th_tabelahash th) {
    int i;
    struct th_id *k;
    for (i = 0; i < HT_DESTROY_TH; i++){
        k = (struct th_id *) malloc (sizeof(struct th_id));
        k->id = i;
        k->th = th;
        pthread_create(&th_threads[i], NULL, (void*) &th_destroy_lines, (void *) k);
    }
    for (i = 0; i < HT_DESTROY_TH; i++)
        pthread_join(th_threads[i], NULL);

    free(th->b);
    free(th);
}
