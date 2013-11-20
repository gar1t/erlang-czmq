// vector.c

#include <stdio.h>
#include <stdlib.h>
#include "vector.h"

void vector_ensure_capacity(vector *v);

void vector_init(vector *v) {
    v->size = 0;
    v->capacity = VECTOR_INITIAL_CAPACITY;
    v->data = malloc(sizeof(void*) * v->capacity);
}

void vector_append(vector *v, void *value) {
    vector_ensure_capacity(v);
    v->data[v->size++] = value;
}

void *vector_get(vector *v, int index) {
    if (index >= v->size || index < 0) {
        return NULL;
    }
    return v->data[index];
}

void vector_set(vector *v, int index, void *value) {
    while (index >= v->size) {
        vector_append(v, 0);
    }
    v->data[index] = value;
}

void vector_ensure_capacity(vector *v) {
    if (v->size >= v->capacity) {
        v->capacity *= 2;
        v->data = realloc(v->data, sizeof(void*) * v->capacity);
    }
}

void vector_free(vector *v) {
    free(v->data);
}

// tests
int main()
{
    vector v;
    vector_init(&v);
    
    int i1 = 10;
    int i2 = 11;
    int i3 = 12;

    vector_append(&v, &i1);
    vector_append(&v, &i2);
    vector_append(&v, &i3);

    printf("vector size is %i\n", v.size);
    printf("element at 0 is %i\n", *(int*)vector_get(&v, 0));
    printf("element at 1 is %i\n", *(int*)vector_get(&v, 1));
    printf("element at 2 is %i\n", *(int*)vector_get(&v, 2));

    int i4 = 13;

    vector_set(&v, 0, &i4);
    printf("after set, element at 0 is %i\n", *(int*)vector_get(&v, 0));

    const int count = 100;
    int i;
    int *j;

    printf("testing %i set operations:\n", count);
    for (i = 0; i < count; i++) {
        j = malloc(sizeof(int));
        *j = i;
        vector_set(&v, i, j);
    }

    int errors = 0;

    for (i = 0; i < count; i++) {
        j = (int*)vector_get(&v, i);
        if (i != *j) {
            printf("- unexpected vector value at pos %i: %i\n", i, *j);
            errors = 1;
        }
    }
    if (!errors) {
        printf("- all values written and read successfully\n");
    }

    return 0;
}
