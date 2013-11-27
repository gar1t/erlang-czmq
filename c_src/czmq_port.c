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

#include "erl_czmq.h"
#include "vector.h"

static int test() {
    printf("Testing erlang-czmq\n");
    vector_test();
    return 0;
}

int main(int argc, char *argv[]) {
    erl_czmq_state state;
    erl_czmq_init(&state);

    int ret;
    if (argc > 1 && strcmp(argv[1], "--test") == 0) {
        ret = test(&state);
    } else {
        ret = erl_czmq_loop(&state);
    }

    return ret;
}
