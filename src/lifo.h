#ifndef LIFO_H
#define LIFO_H

#include <stdint.h>
#include <stddef.h>

typedef struct {
    void         *data;
    size_t        item_size;
    unsigned int  capacity;
    unsigned int  len;
} lifo_t;

void         lifo_alloc_all(lifo_t *q, size_t *count, size_t item_size);
unsigned int lifo_size(const lifo_t *q);
void         lifo_free(lifo_t *q);
int          lifo_enqueue(lifo_t *q, void *item);
int          lifo_dequeue(lifo_t *q, void *item);

#endif