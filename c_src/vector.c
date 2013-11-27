// Copyright (C) 2012, 2013 Garrett Smith <g@rre.tt>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

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

void vector_test()
{
    printf (" * vector: ");

    vector v;
    vector_init(&v);

    // Write a bunch of heap allocated integers
    const int count = 100000;
    int i, *j;
    for (i = 0; i < count; i++) {
        j = malloc(sizeof(int));
        *j = i;
        vector_set(&v, i, j);
    }

    // Read values back and check
    int errors = 0;
    for (i = 0; i < count; i++) {
        j = (int*)vector_get(&v, i);
        if (i != *j) {
            printf(" # unexpected vector value at pos %i: %i\n", i, *j);
            errors++;
        }
    }

    // Free memory and set values to NULL
    for (i = 0; i < count; i++) {
        j = (int*)vector_get(&v, i);
        free(j);
        vector_set(&v, i, NULL);
        j = (int*)vector_get(&v, i);
        if (j) {
            printf(" # unexpected vector value at pos %i: %i\n", i, *j);
            errors++;
        }
    }

    vector_free(&v);

    assert (!errors);

    printf ("OK\n");
}
