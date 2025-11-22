# Jeremy Cuthbert
# CS333 - Jesse Chaney
# Lab 3 Makefile

CC = gcc
DEBUG = -g
DEFINES =
CFLAGS = $(DEBUG) -Wall -Wextra -Wshadow -Wunreachable-code -Wredundant-decls \
	-Wmissing-declarations -Wold-style-definition -Wmissing-prototypes \
	-Wdeclaration-after-statement -Wno-return-local-addr -Werror \
	-Wunsafe-loop-optimizations -Wuninitialized -Wno-unused-parameter $(DEFINES)
LDFLAGS = -lcrypt
PROG = thread_hash

all: $(PROG)

$(PROG): $(PROG).o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(PROG).o: $(PROG).c
	$(CC) $(CFLAGS) -c $<

clean cls:
	rm -f $(PROG) *.o *~ \#*

git:
	if [ ! -d .git ]; then \
	echo "Initializing new Git repository..."; \
	git init; \
	fi
	@echo "Adding source files to Git..."
	git add *.[ch] Makefile
	@echo "Committing changes..."
	git commit -m "Auto commit on $$(date '+%Y-%m-%d %H:%M:%S')"
	@echo "Pushing to remote repository..."
	git push -u origin main

TAR_FILE = ${LOGNAME}_Lab3.tar.gz
tar:
	rm -f $(TAR_FILE)
	tar cvaf $(TAR_FILE) thread_hash.c Makefile
