#!/usr/bin/env python2
# -*- coding: utf-8 -*-
from __future__ import print_function

import os
import sys
import math
import glob
import pexpect as e
import csv


qemu_bin  = "../../x86_64-softmmu/qemu-system-x86_64"
qemu_generic = "-enable-kvm -m 1024 -nographic -kernel /home/julian/src/buildroot/output/images/bzImage -append quiet\ console=ttyS0"

class StdDev:
    def update(self, value):
        self.n      += 1
        self.sum    += value
        self.sum_sq += value*value

    def mean(self):
        if self.n == 0:
            return None
        else:
            return self.sum / self.n

    def stddev(self):
        if self.n < 2:
            return None
        else:
            n  = self.n
            s  = self.sum
            sq = self.sum_sq
            return math.sqrt((sq - s*s/n)/(n-1))

    def format(self):
        res = ""
        mean   = self.mean()
        stddev = self.stddev()
        if mean:
            res += " mean=%.2f" % mean
        if stddev:
            er = 1.96 * stddev / math.sqrt(self.n)
            res += "±%.2f  95%% in [%.2f,%.2f]" % (stddev, mean - er, mean + er)
        return res

    def __init__(self):
        self.n      = 0
        self.sum    = 0
        self.sum_sq = 0

def qemu_quit(p):
    p.sendcontrol('a')
    p.send('x')
    p.expect(e.EOF)
    p.close()

def create_and_configure(qemu_cmd, is_server):
    print("Starting %s VM..." % ("server" if is_server else "client"))
    p = e.spawn("sh -c '%s'" % qemu_cmd, timeout=20)
    p.setecho(False)
    p.expect_exact("buildroot login: ")
    p.sendline("root")
    p.expect("\r\n")
    p.sendline("ifconfig eth0 up %s && echo return $?" % ("10.0.0.1" if is_server else "10.0.0.2"))
    r = p.expect (["return 0", "No such device"])
    if r != 0:
        print("Network configuration failed: %d" % r, file=sys.stderr)
        exit(1)
    if is_server:
        p.sendline("netserver")
        p.expect_exact(r"Starting netserver with host 'IN(6)ADDR_ANY' port '12865' and family AF_UNSPEC")
        p.sendline("iperf -s")
        p.expect_exact("Server listening on TCP port 5001")
    return p

def netperf_rr_like(client, test):
    client.sendline("netperf -t %s -H 10.0.0.1" % test)
    client.expect_exact("Socket Size   Request  Resp.   Elapsed  Trans.")
    client.expect_exact("Send   Recv   Size     Size    Time     Rate")
    client.expect_exact("bytes  Bytes  bytes    bytes   secs.    per sec")
    client.expect(r"\d+\s+\d+\s+\d+\s+\d+\s+\d+\.\d+\s+(\d+\.\d+)\s*\r\n")
    return float(client.match.group(1))

def clear_line():
    print("[2K\r", end="")

def repeat_benchmark(name, repeat, thunk):
    result = []
    stddev_gen = StdDev()
    for i in range(repeat):
        clear_line()
        print("Running %s (%d/%d). %s" % (name, i+1, repeat, stddev_gen.format()), end="")
        sys.stdout.flush()
        v = thunk()
        stddev_gen.update(v)
        result.append(v)
    clear_line()
    print("%s: %s" % (name, stddev_gen.format()))
    return result


repeat = 20
def run_benchmark(prefix, client, server):
    return [
        [prefix + "_udp_rr"] + repeat_benchmark("UDP Request/Response", repeat,
                                               lambda: 1000000/netperf_rr_like(client, "UDP_RR")),
        [prefix + "_tcp_rr"] + repeat_benchmark("TCP Request/Response", repeat,
                                               lambda: 1000000/netperf_rr_like(client, "TCP_RR")),
        # [prefix + "_tcp_cc"] + repeat_benchmark("TCP Connect/Close", repeat,
        #                                        lambda: 1000000/netperf_rr_like(client, "TCP_CC")),
        # [prefix + "_tcp_crr"] + repeat_benchmark("TCP Connect/Request/Response", repeat,
        #                                          lambda: 1000000/netperf_rr_like(client, "TCP_CRR")),
        ]


def run_externalpci_benchmark():
    print("\n--- externalpci ---")
    qemu_externalpci_args = "-mem-path /tmp -device externalpci,socket=/tmp/externalpci -net none "
    qemu_cmd = "%s %s %s" % (qemu_bin, qemu_externalpci_args, qemu_generic)

    switch = e.spawn("./virtio-server", logfile=sys.stdout)
    switch.expect_exact("Ready.")
    print("Switch is running.")

    server = create_and_configure(qemu_cmd, True)
    client = create_and_configure(qemu_cmd, False)
    
    results = run_benchmark("epci", client, server)
    
    qemu_quit(client)
    qemu_quit(server)
    switch.close()

    return results

class CommandFailed(BaseException):
    pass

def create_macvtap(netif, macvtap, mac):
    """Create a macvtap devices connected to netif. Returns the name of the 
    corresponding tap device."""
    output, ex = e.run("sudo ip link add link %s name %s address %s type macvtap mode bridge" % (netif, macvtap, mac),
                       withexitstatus = True)
    if ex != 0:
        print(output)
        raise CommandFailed()
    e.run("sudo ip link set dev %s up" % macvtap)
    tap_files = glob.glob("/sys/class/net/%s/tap*" % macvtap)
    assert len(tap_files) == 1
    devnode = "/dev/" + os.path.basename(tap_files[0])
    return devnode

def delete_macvtap(macvtap):
    e.run("sudo ip link delete %s type macvtap" % macvtap)

def run_vhost_benchmark():
    print("\n--- vhost ---")
    cleanup_fn = []
    netif="eth0"
    try:
        def mt(name, tapname, mac):
            tap = create_macvtap(netif, tapname, mac)
            cleanup_fn.append(lambda: delete_macvtap(tapname))
            return tap

        client_mac = "1a:54:0b:ca:bc:10"
        qemu_vhost_args = " -netdev type=tap,id=guest,vhost=on,fd=3 -device virtio-net-pci,netdev=guest,mac=%s  3<>%s"
        qemu_vhost_client_args = qemu_vhost_args % (client_mac, mt(netif, "macvtap0", client_mac))
        client = create_and_configure("%s %s %s" % (qemu_bin, qemu_generic, qemu_vhost_client_args), False)

        server_mac = "1a:54:0b:ca:bc:20"
        qemu_vhost_server_args = qemu_vhost_args % (server_mac, mt(netif, "macvtap1", server_mac))
        server = create_and_configure("%s %s %s" % (qemu_bin, qemu_generic, qemu_vhost_server_args), True)

        results = run_benchmark("vhost", client, server)
    
        qemu_quit(client)
        qemu_quit(server)

        return results

    finally:
        cleanup_fn.reverse()
        for f in cleanup_fn:
            f()

print("Let the benchmarking commence!")

#client.logfile = sys.stdout

vhost_results       = run_vhost_benchmark()
externalpci_results = run_externalpci_benchmark()



with open('results.csv', 'wb') as csvfile:
    writer = csv.writer(csvfile)
    for r in externalpci_results + vhost_results:
        writer.writerow(r)




        
