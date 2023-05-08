c_src = $(shell find . -name "*.cpp")

sampler:
	g++ -g $(c_src) -o $@

clean:
	rm -fR sampler
	rm -fR *.txt