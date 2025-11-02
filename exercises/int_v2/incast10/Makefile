# SPDX-License-Identifier: Apache-2.0
BMV2_SWITCH_EXE = simple_switch_grpc
TOPO = incast10-topo.json
SENDER_HOST = h1
COLLECTOR_HOST = h_report
EXTRA_ARG = s1 ./my_controller.py
SENDER_ARGS = 10.0.20.20 "Hello"
COLLECTOR_PKT_COUNT = 100
NOISE_COMMANDS = echo 'h2 ./send.py 10.0.20.20 "Hello" &';echo 'h3 ./send.py 10.0.20.20 "Hello" &';echo 'h4 ./send.py 10.0.20.20 "Hello" &';echo 'h5 ./send.py 10.0.20.20 "Hello" &';echo 'h6 ./send.py 10.0.20.20 "Hello" &';echo 'h7 ./send.py 10.0.20.20 "Hello" &';echo 'h8 ./send.py 10.0.20.20 "Hello" &';echo 'h9 ./send.py 10.0.20.20 "Hello" &';echo 'h10 ./send.py 10.0.20.20 "Hello" &';

# Assuming the utils directory is two levels up
include ../../../utils/Makefile