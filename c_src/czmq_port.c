/*  =========================================================================
    czmq_port - An Erlang port wrapper for CZMQ

    -------------------------------------------------------------------------
    Copyright (c) 2013-214 Garrett Smith <g@rre.tt>
    Copyright other contributors as noted in the AUTHORS file.

    This file is part of erlang-czmq: https://github.com/gar1t/erlang-czmq

    This is free software; you can redistribute it and/or modify it under
    the terms of the GNU Lesser General Public License as published by the
    Free Software Foundation; either version 3 of the License, or (at your
    option) any later version.

    This software is distributed in the hope that it will be useful, but
    WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABIL-
    ITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General
    Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with this program. If not, see <http://www.gnu.org/licenses/>.
    =========================================================================
*/

#include "erl_czmq.h"
#include "vector.h"

static int test() {
    printf("Testing erlang-czmq\n");
    vector_test();
    return 0;
}

int main(int argc, char *argv[]) {
    erl_czmq_state *state = malloc(sizeof(*state));
    erl_czmq_init(state);

    int ret;
    if (argc > 1 && strcmp(argv[1], "--test") == 0) {
        ret = test(state);
    } else {
        ret = erl_czmq_run(state);
    }

    free(state);
    return ret;
}
