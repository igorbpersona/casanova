#ifndef HASH_H
#define HASH_H

#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>
#include "../lista/lista.h"

#define HT_MAX_BITS 18
#define HT_MAX_SIZE (1<<(HT_MAX_BITS))
#define th_map_int(a) ((a)&( ( 1<<( HT_MAX_BITS ) ) -1))

#define HT_DESTROY_TH 20
#define HT_INIT_TH 1


typedef struct {
    unsigned int count;
    lista_t *b;
} th_tabelahash_t;

typedef th_tabelahash_t* th_tabelahash;

th_tabelahash th_init ();

void th_insert (unsigned char *, unsigned char *, th_tabelahash);

unsigned char* th_get (unsigned char *, th_tabelahash);

void th_destroy (th_tabelahash);

#endif
