rebar=./rebar

compile:
	$(rebar) compile

clean:
	$(rebar) clean
	cd c_src; make clean
