# SPDX-License-Identifier: Apache-2.0
BUILD_DIR = build
PCAP_DIR = pcaps
LOG_DIR = logs

P4C = p4c-bm2-ss
P4C_ARGS += --p4runtime-files $(BUILD_DIR)/$(basename $@).p4.p4info.txtpb

RUN_SCRIPT = ../../../utils/run_exercise.py

ifndef TOPO
TOPO = topology.json
endif

source = $(wildcard ../*.p4) # MODIFIED
compiled_json := $(notdir $(source:.p4=.json)) # MODIFIED

ifndef DEFAULT_PROG
DEFAULT_PROG = $(wildcard ../*.p4) # MODIFIED
endif
DEFAULT_JSON = $(BUILD_DIR)/$(notdir $(DEFAULT_PROG:.p4=.json)) # MODIFIED

# Define NO_P4 to start BMv2 without a program
ifndef NO_P4
run_args += -j $(DEFAULT_JSON)
endif

# Set BMV2_SWITCH_EXE to override the BMv2 target
ifdef BMV2_SWITCH_EXE
run_args += -b $(BMV2_SWITCH_EXE)
endif

# --- Config for 'make test' ---
SENDER_SCRIPT ?= send.py
SENDER_HOST ?= h1
SENDER_ARGS ?= 10.0.3.3 "Hello"

COLLECTOR_SCRIPT ?= report.py
COLLECTOR_HOST ?= h3
COLLECTOR_IFACE ?= eth0
COLLECTOR_OUTPUT ?= ../reports/report-$(TOPO)
COLLECTOR_PKT_COUNT ?= 10
COLLECTOR_ARGS ?= $(COLLECTOR_IFACE) $(COLLECTOR_OUTPUT) $(COLLECTOR_PKT_COUNT)
# ------------------------------

all: run

run: build
	sudo PATH=$(PATH) ${P4_EXTRA_SUDO_OPTS} python3 $(RUN_SCRIPT) -t $(TOPO) $(run_args)

stop:
	sudo PATH=$(PATH) `which mn` -c

build: dirs $(compiled_json)

# MODIFIED
%.json: ../%.p4
	$(P4C) --p4v 16 $(P4C_ARGS) -o $(BUILD_DIR)/$@ $<

dirs:
	mkdir -p $(BUILD_DIR) $(PCAP_DIR) $(LOG_DIR)

test: build
	@echo "Starting Mininet and running test..."
	( \
		sleep 2; \
		echo "$(EXTRA_ARG)"; \
		echo "$(COLLECTOR_HOST) ./$(COLLECTOR_SCRIPT) $(COLLECTOR_ARGS) > ./$(COLLECTOR_HOST).log 2>&1 &"; \
		$(NOISE_COMMANDS) \
		echo "$(SENDER_HOST) ./$(SENDER_SCRIPT) $(SENDER_ARGS)"; \
		echo "exit"; \
	) | sudo PATH=$(PATH) ${P4_EXTRA_SUDO_OPTS} python3 $(RUN_SCRIPT) -t $(TOPO) $(run_args)

clean: stop
	rm -f *.pcap
	rm -rf $(BUILD_DIR) $(PCAP_DIR) $(LOG_DIR)
	rm -f *.log
	# Clean up test artifacts

.PHONY: all run stop build dirs clean test