c_src = $(shell find . -name "*.cpp")

disassembler.out:
	g++ -g $(c_src) -o $@

clean:
	rm -fR disassembler.out
	rm -fR *.txt