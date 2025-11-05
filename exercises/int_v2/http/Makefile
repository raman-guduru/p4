P4_SRCS = ../int_md.p4
BMV2_SWITCH_EXE = simple_switch_grpc
TOPO = http-linear5-topo.json
EXTRA_ARG = s1 ./my_controller.py

# --- Host Commands & Logging ---
COLLECTOR_HOST = h_report
# Override SENDER_HOST to run on h1
SENDER_HOST = h1
# Override SENDER_ARGS to point to h2's IP (10.0.5.5)
SENDER_ARGS = > ./h1_send.log 2>&1
# Command to run the receiver on h2 and log its output.
NOISE_COMMANDS = echo "h2 python3 -u ./receive.py > ./h2_receive.log 2>&1 &";sleep 2;

include ../../../utils/Makefile