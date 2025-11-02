# SPDX-License-Identifier: Apache-2.0
BMV2_SWITCH_EXE = simple_switch_grpc
TOPO = incast-topo.json
SENDER_HOST = h1
COLLECTOR_HOST = h_report
EXTRA_ARG = s1 ./my_controller.py
SENDER_ARGS = 10.0.2.4 "Hello"
COLLECTOR_PKT_COUNT = 30
NOISE_COMMANDS = echo 'h2 ./send.py 10.0.2.4 "Hello" &';echo 'h3 ./send.py 10.0.2.4 "Hello" &';

# Assuming the utils directory is two levels up
include ../../../utils/Makefile