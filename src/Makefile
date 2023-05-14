c_src = $(shell find . -name "*.cpp")
lib = capstone
EXEC = disassembler.out
debug: $(c_src)
	g++ -g3 $(c_src) -o $(EXEC) -L./incs/ -l$(lib)
release: $(c_src)
	g++ -O2 $(c_src) -o $(EXEC) -L./incs/ -l$(lib)

clean:
	rm -fR disassembler.out
	rm -fR *.txt