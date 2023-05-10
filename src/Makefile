c_src = $(shell find . -name "*.cpp")
lib = capstone
disassembler.out:
	g++ -g $(c_src) -o $@ -L./incs/ -l$(lib)

clean:
	rm -fR disassembler.out
	rm -fR *.txt