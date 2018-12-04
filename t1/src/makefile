CC = gcc
INCLUDES = -I/usr/include/glib-2.0 $(shell pkg-config --cflags --libs glib-2.0) -lpthread -lcrypto
CFLAGS = -Wall -O3 -D_REENTRANT
PROGRAM_NAME := casanova
MAIN_PROGRAM := src/$(PROGRAM_NAME).c


MODULES   := locking hash lista
SRC_DIR   := $(addprefix src/,$(MODULES))
BUILD_DIR := $(addprefix build/,$(MODULES))

SRC       := $(foreach sdir,$(SRC_DIR),$(wildcard $(sdir)/*.c))
OBJ       := $(patsubst src/%.c,build/%.o,$(SRC))
#INCLUDES  := $(addprefix -I,$(SRC_DIR))

vpath %.c $(SRC_DIR)
vpath %.h $(SRC_DIR)

define make-goal
$1/%.o: %.c %.h
	$(CC) $(CFLAGS) -c $$< -o $$@
endef

.PHONY: all checkdirs clean purge

all: checkdirs $(PROGRAM_NAME) put_client get_client

$(PROGRAM_NAME): $(OBJ) $(MAIN_PROGRAM) src/casanova.h
	$(CC) $(CFLAGS) $(MAIN_PROGRAM) -o $@ $(OBJ) $(INCLUDES)

put_client: src/put_client.c src/casanova.h
	$(CC) $(CFLAGS) -o put_client src/put_client.c

get_client: src/get_client.c src/casanova.h
	$(CC) $(CFLAGS) -o get_client src/get_client.c

checkdirs: $(BUILD_DIR)

$(BUILD_DIR):
	@mkdir -p $@

clean:
	@rm -rf build
	@rm -f *.o *.*~ *~ telefones server_get_socket server_put_socket
	@rm -rf $(PROGRAM_NAME) put_client get_client

$(foreach bdir,$(BUILD_DIR),$(eval $(call make-goal,$(bdir))))

