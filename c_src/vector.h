// vector.h

#ifndef __VECTOR_H_INCLUDED__
#define __VECTOR_H_INCLUDED__

#define VECTOR_INITIAL_CAPACITY 100;

typedef struct {
    int size;
    int capacity;
    void **data;
} vector;

void vector_init(vector *v);

void vector_append(vector *v, void *value);

void *vector_get(vector *v, int index);

void vector_set(vector *v, int index, void *value);

void vector_free(vector *v);

void vector_test();

#endif
