CC := clang
CFLAGS := -g -Wall -Wno-deprecated-declarations -Werror

# Set compiler flags for macOS using brew, or point to Charlie's ssl library on MathLAN
SYSTEM := $(shell uname -s)
ifeq ($(SYSTEM),Darwin)
  CFLAGS += -I$(shell brew --prefix openssl)/include -L$(shell brew --prefix openssl)/lib
else
  CFLAGS += -I/home/curtsinger/.local/include -L/home/curtsinger/.local/lib
endif

all: password-cracker

clean:
	rm -rf password-cracker password-cracker.dSYM

password-cracker: password-cracker.c
	$(CC) $(CFLAGS) -o password-cracker password-cracker.c -lcrypto -lpthread -lm

zip:
	@echo "Generating password-cracker.zip file to submit to Gradescope..."
	@zip -q -r password-cracker.zip . -x .git/\* .vscode/\* inputs/\* .clang-format .gitignore password-cracker
	@echo "Done. Please upload password-cracker.zip to Gradescope."

format:
	@echo "Reformatting source code."
	@clang-format -i --style=file $(wildcard *.c) $(wildcard *.h)
	@echo "Done."

.PHONY: all clean zip format
