PROJECT = czmq

COMPILE_FIRST=zmq_gen_benchmark.erl
include erlang.mk

app::
	cd c_src; make

clean::
	cd c_src; make clean

opts=
shell: compile
	erl -pa ebin -s czmq_reloader ${opts}
