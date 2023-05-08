c_src = $(shell find . -name "*.cpp")

sampler:
	g++ $(c_src) -o $@

clean:
	rm sampler