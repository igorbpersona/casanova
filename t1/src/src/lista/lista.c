#include "lista.h"

void lista_init (lista_t *l) {
    l->size = 0;
    l->head = NULL;
    l->tail = l->head;
    sem_init(&l->mutex, 0, 1);
}

void lista_insert (lista_t *l, unsigned char *key, unsigned char *value) {
    int elem_target, i;
    lista_block_t *block;
    sem_wait(&l->mutex);
    elem_target = l->size % LIST_BLOCK_STORAGE;
    if (elem_target == 0) {
        block = malloc(sizeof(lista_block_t));
        block->next = NULL;
        if (l->size == 0) {
            l->head = block;
            l->tail = l->head;
        } else {
            l->tail->next = block;
            l->tail = block;
        }
    }
    block = l->tail;
    l->size++;
    sem_post(&l->mutex);
    for (i = 0; i < 16; i++) {
        block->data[elem_target * LIST_BLOCK_DATA_SIZE + i] = key[i];
        block->data[elem_target * LIST_BLOCK_DATA_SIZE + i + 16] = value[i];
    }
}

unsigned char *lista_find (lista_t *l, unsigned char *key) {
    int i, cur_block;
    lista_block_t *block;
    block = l->head;
    cur_block = 0;
    while (block != NULL) {
        for (i = 0; i < LIST_BLOCK_STORAGE && (cur_block * LIST_BLOCK_STORAGE + i) < l->size; i++) {
            if (memcmp(key, &block->data[LIST_BLOCK_DATA_SIZE*i], 16) == 0)
                return &block->data[LIST_BLOCK_DATA_SIZE*i+16];
        }
        block = block->next;
        cur_block++;
    }
    return NULL;
}

void lista_destroy (lista_t *l) {
    lista_block_t *block, *n_block;
    block = l->head;
    while (block != NULL) {
        n_block = block->next;
        free(block);
        block = n_block;
    }
}
