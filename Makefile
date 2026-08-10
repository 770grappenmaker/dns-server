CFLAGS := -Wall -Wextra -Wno-pointer-sign -Wno-discarded-qualifiers -Wno-sign-compare
CC := gcc
LDFLAGS := -Iinclude

SRC_DIR := src
OBJ_DIR := obj
BIN_DIR := bin
TEMP_DIRS := $(OBJ_DIR) $(BIN_DIR)

SOURCES := $(wildcard $(SRC_DIR)/*.c)
DEPS := $(patsubst $(SRC_DIR)/%.c,$(OBJ_DIR)/%.d,$(SOURCES))
OBJS := $(patsubst $(SRC_DIR)/%.c,$(OBJ_DIR)/%.o,$(SOURCES))
BINARIES := dns_server

BIN_OUTS := $(addprefix $(BIN_DIR)/,$(BINARIES))

.PHONY: clean all

all: $(BIN_OUTS)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c | $(OBJ_DIR)
	@echo "CC $@"
	@$(CC) $(LDFLAGS) $(CFLAGS) -MMD -MP -c "$<" -o "$@"

$(BIN_OUTS): $(OBJS) | $(BIN_DIR)
	@echo "LD $@"
	@$(CC) $(LDFLAGS) $(CFLAGS) -o "$@" $^

$(TEMP_DIRS):
	@mkdir -p "$@"

clean:
	rm -rf $(TEMP_DIRS)

-include $(DEPS)
