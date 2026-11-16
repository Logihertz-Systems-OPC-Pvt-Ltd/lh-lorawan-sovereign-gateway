CC ?= gcc
CFLAGS ?= -std=c11 -O2 -Wall -Wextra -Werror -pedantic -Iinclude -D_POSIX_C_SOURCE=200809L
LDFLAGS ?= -lm

SRCS = src/aes128_cmac.c \
       src/lorawan_mac.c \
       src/json_parser.c \
       src/lorawan_auditor.c \
       src/exporters.c

CLI_SRCS = $(SRCS) src/main.c
TEST_SRCS = $(SRCS) tests/test_runner.c

BIN_DIR = bin
TEST_DIR = tests
TARGET = $(BIN_DIR)/lh-lorawan
TEST_TARGET = $(TEST_DIR)/test_runner

.PHONY: all test clean

all: $(TARGET)

$(TARGET): $(CLI_SRCS)
	@mkdir -p $(BIN_DIR)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(TEST_TARGET): $(TEST_SRCS)
	@mkdir -p $(TEST_DIR)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

test: $(TEST_TARGET) $(TARGET)
	@echo "Running Logihertz Sovereign LoRaWAN test suite..."
	@./$(TEST_TARGET)
	@echo "Running CLI verification smoke tests..."
	@./$(TARGET) --version
	@./$(TARGET) --help > /dev/null
	@./$(TARGET) audit fixtures/hardened_lorawan_policy.json > /dev/null
	@./$(TARGET) audit fixtures/hardened_lorawan_policy.json --format=json > /dev/null
	@./$(TARGET) audit fixtures/hardened_lorawan_policy.json --format=sarif > /dev/null
	@./$(TARGET) calc-toa --sf=7 --bw=125 --payload=16 --region=IN865 > /dev/null
	@./$(TARGET) calc-toa --sf=12 --bw=125 --payload=23 --region=IN865 --format=json > /dev/null
	@echo "All Logihertz LoRaWAN tests and CLI smoke checks completed successfully!"

clean:
	rm -rf $(TARGET) $(TEST_TARGET) *.o /tmp/lh-lorawan* build/ dist/
