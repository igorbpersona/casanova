#ifndef LIST_H
#define LIST_H

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <semaphore.h>

#define LIST_BLOCK_STORAGE 15
#define LIST_BLOCK_DATA_SIZE 32
#define LIST_BLOCK_SIZE 480

typedef struct List_block {
    unsigned char data[LIST_BLOCK_SIZE];
    void *align1, *align2, *align3;
    struct List_block *next;
} lista_block_t;

typedef struct {
    int size;
    lista_block_t *head, *tail;
    sem_t mutex;
} lista_t;

void lista_init (lista_t *);

void lista_insert (lista_t *, unsigned char *, unsigned char *);

unsigned char *lista_find (lista_t *, unsigned char *);

void lista_destroy (lista_t *);

#endif
