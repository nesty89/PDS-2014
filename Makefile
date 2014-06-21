NAME=flow
COMPILER=g++

FILES=Flow.hpp Flow.cc

ALL: $(FILES)
	$(COMPILER) -O2 -D __STDC_LIMIT_MACROS -D __STDC_FORMAT_MACROS -Wall -std=c++0x -o $(NAME) $(FILES)

clean:
	rm -f *.o $(NAME) *~ *.exe
