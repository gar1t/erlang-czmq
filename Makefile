rebar=./rebar

compile:
	$(rebar) compile

clean:
	$(rebar) clean
	cd c_src; make clean

opts=
shell: compile
	erl -pa ebin -s czmq_reloader ${opts}
