# no-ping

This is a simple eBPF program written in P4, and compiled using the eBPF backend. </br>
The program drops all incoming ICMP packets.

## How to try this?

Reference: https://github.com/p4lang/p4c/tree/master/backends/ebpf

### Step 1: Generating code from .p4 file
`p4c-ebpf no_ping.p4 -o no_ping.c`

### Step 2: Generate eBPF program
`make -f ../p4c/backends/ebpf/runtime/kernel.mk BPFOBJ=no_ping.o P4FILE=no_ping.p4`

### Step 3: Attach as TC filter
`tc qdisc add dev IFACE clsact`
`tc filter add dev IFACE egress bpf da obj no_ping.o section prog verbose`

### Step 4: Try pinging yourself!
Other machines should not be able to ping you ;)

### Step 4: Removing the filter
`tc filter delete dev IFACE egress`
