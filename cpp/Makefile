CXX ?= g++
AR ?= ar
CXXFLAGS ?= -std=c++20 -O2 -Wall -Wextra -Wpedantic -Werror -fstack-protector-strong -D_FORTIFY_SOURCE=3
CPPFLAGS := -Iinclude $(shell pkg-config --cflags openssl)
LDFLAGS := $(shell pkg-config --libs libcrypto)

BUILD_DIR := build
LIBRARY := $(BUILD_DIR)/libqprotect_cpp.a
SELFTEST := $(BUILD_DIR)/qprotect_cpp_selftest
TOOL := $(BUILD_DIR)/qprotect_cpp_tool
UNITTESTS := $(BUILD_DIR)/qprotect_cpp_unittests

SOURCES := \
    src/crypto_context.cpp \
    src/algorithms.cpp \
    src/envelope.cpp \
    src/keys.cpp \
    src/json_minimal.cpp \
    src/identity.cpp \
    src/self_test.cpp \
    src/secure_file.cpp \
    src/disk.cpp

OBJECTS := $(patsubst src/%.cpp,$(BUILD_DIR)/%.o,$(SOURCES))

.PHONY: all test integration clean

all: $(LIBRARY) $(SELFTEST) $(TOOL)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(BUILD_DIR)/%.o: src/%.cpp | $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) -c $< -o $@

$(LIBRARY): $(OBJECTS)
	$(AR) rcs $@ $^

$(SELFTEST): $(BUILD_DIR)/selftest_main.o $(LIBRARY)
	$(CXX) $(CXXFLAGS) -Iinclude $< $(LIBRARY) $(LDFLAGS) -o $@

$(TOOL): $(BUILD_DIR)/qprotect_tool.o $(LIBRARY)
	$(CXX) $(CXXFLAGS) -Iinclude -Isrc $< $(LIBRARY) $(LDFLAGS) -o $@

$(UNITTESTS): $(BUILD_DIR)/unit_tests.o $(LIBRARY)
	$(CXX) $(CXXFLAGS) -Iinclude $< $(LIBRARY) $(LDFLAGS) -o $@

$(BUILD_DIR)/selftest_main.o: apps/selftest_main.cpp | $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) -Iinclude -c $< -o $@

$(BUILD_DIR)/qprotect_tool.o: apps/qprotect_tool.cpp | $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) -Iinclude -Isrc -c $< -o $@

$(BUILD_DIR)/unit_tests.o: tests/unit_tests.cpp | $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) -Iinclude -Isrc -c $< -o $@

test: $(SELFTEST) $(UNITTESTS)
	$(SELFTEST)
	$(UNITTESTS)

integration: all $(UNITTESTS)
	python3 tests/integration_interop.py

clean:
	rm -rf $(BUILD_DIR)
