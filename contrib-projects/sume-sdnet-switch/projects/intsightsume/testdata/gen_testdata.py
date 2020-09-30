#!/usr/bin/env python

#
# Copyright (c) 2020 Jonatas Adilson Marques
# All rights reserved.
#
# Copyright (c) 2017 Stephen Ibanez
# All rights reserved.
#
# This software was developed by Stanford University and the University of Cambridge Computer Laboratory 
# under National Science Foundation under Grant No. CNS-0855268,
# the University of Cambridge Computer Laboratory under EPSRC INTERNET Project EP/H040536/1 and
# by the University of Cambridge Computer Laboratory under DARPA/AFRL contract FA8750-11-C-0249 ("MRC2"), 
# as part of the DARPA MRC research programme.
#
# @NETFPGA_LICENSE_HEADER_START@
#
# Licensed to NetFPGA C.I.C. (NetFPGA) under one or more contributor
# license agreements.  See the NOTICE file distributed with this work for
# additional information regarding copyright ownership.  NetFPGA licenses this
# file to you under the NetFPGA Hardware-Software License, Version 1.0 (the
# "License"); you may not use this file except in compliance with the
# License.  You may obtain a copy of the License at:
#
#   http://www.netfpga-cic.org
#
# Unless required by applicable law or agreed to in writing, Work distributed
# under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
# CONDITIONS OF ANY KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations under the License.
#
# @NETFPGA_LICENSE_HEADER_END@
#


from switch_calc_headers import * 
from nf_sim_tools import *
import random
from collections import OrderedDict
import sss_sdnet_tuples


########################
# pkt generation tools #
########################

pktsApplied = []
pktsExpected = []

# Pkt lists for SUME simulations
nf_applied = OrderedDict()
nf_applied[0] = []
nf_applied[1] = []
nf_applied[2] = []
nf_applied[3] = []
nf_expected = OrderedDict()
nf_expected[0] = []
nf_expected[1] = []
nf_expected[2] = []
nf_expected[3] = []

dma0_expected = []

nf_port_map = {"nf0":0b00000001, "nf1":0b00000100, "nf2":0b00010000, "nf3":0b01000000, "dma0":0b00000010}
nf_id_map = {"nf0":0, "nf1":1, "nf2":2, "nf3":3}

sss_sdnet_tuples.clear_tuple_files()

def applyPkt(pkt, ingress, time):
    pktsApplied.append(pkt)
    sss_sdnet_tuples.sume_tuple_in['src_port'] = nf_port_map[ingress]
    sss_sdnet_tuples.sume_tuple_in['pkt_len'] = len(pkt)
    sss_sdnet_tuples.sume_tuple_expect['src_port'] = nf_port_map[ingress]
    sss_sdnet_tuples.sume_tuple_expect['pkt_len'] = len(pkt)
    pkt.time = time
    nf_applied[nf_id_map[ingress]].append(pkt)

def expPkt(pkt, egress, digest=None):
    pktsExpected.append(pkt)
    sss_sdnet_tuples.sume_tuple_expect['dst_port'] = nf_port_map[egress]
    if digest is not None:
        sss_sdnet_tuples.sume_tuple_expect['send_dig_to_cpu'] = 1
        for k, v in digest.items():
            sss_sdnet_tuples.dig_tuple_expect[k] = v
        dma0_expected.append(Digest(**digest))
    else:
        sss_sdnet_tuples.sume_tuple_expect['send_dig_to_cpu'] = 0
        for k in sss_sdnet_tuples.dig_tuple_expect.keys():
            sss_sdnet_tuples.dig_tuple_expect[k] = 0
    sss_sdnet_tuples.write_tuples()
    if egress in ["nf0","nf1","nf2","nf3"]:
        nf_expected[nf_id_map[egress]].append(pkt)
    elif egress == 'bcast':
        nf_expected[0].append(pkt)
        nf_expected[1].append(pkt)
        nf_expected[2].append(pkt)
        nf_expected[3].append(pkt)

def print_summary(pkts):
    for pkt in pkts:
        print "summary = ", pkt.summary()

def write_pcap_files():
    wrpcap("src.pcap", pktsApplied)
    wrpcap("dst.pcap", pktsExpected)

    for i in nf_applied.keys():
        if (len(nf_applied[i]) > 0):
            wrpcap('nf{0}_applied.pcap'.format(i), nf_applied[i])

    for i in nf_expected.keys():
        if (len(nf_expected[i]) > 0):
            wrpcap('nf{0}_expected.pcap'.format(i), nf_expected[i])

    for i in nf_applied.keys():
        print "nf{0}_applied times: ".format(i), [p.time for p in nf_applied[i]]
    
    if len(dma0_expected) > 0:
        wrpcap('dma0_expected.pcap', dma0_expected)

#####################
# generate testdata #
#####################

MAC1 = "08:11:11:11:11:08"
MAC2 = "08:22:22:22:22:08"
MAC0i = '00:18:3E:02:0D:A0'
MAC0o = '00:00:00:00:01:00'
MAC1i = '00:18:3E:02:0D:A1'
MAC1o = '00:00:00:00:02:00'
MAC2i = '00:18:3E:02:0D:A2'
MAC2o = '00:00:00:00:03:00'
MAC3i = '00:18:3E:02:0D:A3'
MAC3o = '00:00:00:00:04:00'
pktCnt = 0
cPktCnt = 0
rPktCnt = 0

INDEX_WIDTH = 4
REG_DEPTH = 2**INDEX_WIDTH

NUM_KEYS = 4
lookup_table = {0: 0x00000001, 1: 0x00000010, 2: 0x00000100, 3: 0x00001000}

# Test the addition functionality
# def test_add(OP1, OP2): 
#     # Create a packet to test the addition operation using OP1 and OP2
#     # and apply it to the switch. Also create the expected packet and
#     # indicate it should be expected on a particular interface.
#     global pktCnt
#     pkt = Ether(dst=MAC2, src=MAC1) / Calc(op1=OP1, opCode=ADD_OP, op2=OP2, result=0)
#     pkt = pad_pkt(pkt, 64)
#     applyPkt(pkt, 'nf0', pktCnt)
#     pktCnt += 1
#     pkt = Ether(dst=MAC1, src=MAC2) / Calc(op1=OP1, opCode=ADD_OP, op2=OP2, result=OP1+OP2)
#     pkt = pad_pkt(pkt, 64)
#     expPkt(pkt, 'nf0')

# # Test the subtraction functionality
# def test_sub(OP1, OP2):
#     global pktCnt
#     pkt = Ether(dst=MAC2, src=MAC1) / Calc(op1=OP1, opCode=SUB_OP, op2=OP2, result=0)
#     pkt = pad_pkt(pkt, 64)
#     applyPkt(pkt, 'nf0', pktCnt)
#     pktCnt += 1
#     pkt = Ether(dst=MAC1, src=MAC2) / Calc(op1=OP1, opCode=SUB_OP, op2=OP2, result=OP1-OP2)
#     pkt = pad_pkt(pkt, 64)
#     expPkt(pkt, 'nf0')

# # Test the key-vaule lookup functionality 
# def test_lookup(OP1):
#     global pktCnt
#     key = (OP1 % NUM_KEYS)
#     pkt = Ether(dst=MAC2, src=MAC1) / Calc(op1=key, opCode=LOOKUP_OP, op2=0, result=0)
#     pkt = pad_pkt(pkt, 64)
#     applyPkt(pkt, 'nf0', pktCnt)
#     pktCnt += 1
#     pkt = Ether(dst=MAC1, src=MAC2) / Calc(op1=key, opCode=LOOKUP_OP, op2=0, result=lookup_table[key])
#     pkt = pad_pkt(pkt, 64)
#     expPkt(pkt, 'nf0')   

# # Test the register functionality
# def test_reg(OP1, OP2): 
#     global pktCnt
#     index = OP1 % REG_DEPTH
#     val = OP2
#     # test set reg
#     pkt = Ether(dst=MAC2, src=MAC1) / Calc(op1=index, opCode=SET_REG_OP, op2=val, result=0)
#     pkt = pad_pkt(pkt, 64)
#     applyPkt(pkt, 'nf0', pktCnt)
#     pktCnt += 1
#     pkt = Ether(dst=MAC1, src=MAC2) / Calc(op1=index, opCode=SET_REG_OP, op2=val, result=0)
#     pkt = pad_pkt(pkt, 64)
#     expPkt(pkt, 'nf0')
#     # test add reg
#     pkt = Ether(dst=MAC2, src=MAC1) / Calc(op1=index, opCode=ADD_REG_OP, op2=val, result=0) 
#     pkt = pad_pkt(pkt, 64)
#     applyPkt(pkt, 'nf0', pktCnt)
#     pktCnt += 1
#     pkt = Ether(dst=MAC1, src=MAC2) / Calc(op1=index, opCode=ADD_REG_OP, op2=val, result=val+val) 
#     pkt = pad_pkt(pkt, 64)
#     expPkt(pkt, 'nf0')

def test_intsight_modification():
    global pktCnt
    pkt = Ether(dst=MAC1i, src=MAC1o) / IntSight(epoch=23, path_src=23, path_length=1, path_code=1, contention_points=0, e2e_delay=0xa00, ingress_packets=pktCnt, ingress_bytes=64, next_header=0)
    pkt = pad_pkt(pkt, 64)
    applyPkt(pkt, 'nf1', pktCnt)
    pktCnt += 1
    pkt = Ether(dst=MAC2o, src=MAC2i) / IntSight(epoch=23, path_src=23, path_length=2, path_code=1, contention_points=0b10, e2e_delay=0xaa0, ingress_packets=pktCnt - 1, ingress_bytes=64, next_header=0)
    pkt = pad_pkt(pkt, 64)
    expPkt(pkt, 'nf2')

def test_intsight_creation():
    global pktCnt
    global cPktCnt
    pkt = Ether(dst=MAC0i, src=MAC0o)
    pkt = pad_pkt(pkt, 64)
    applyPkt(pkt, 'nf0', pktCnt)
    pktCnt += 1
    cPktCnt += 1
    pkt = Ether(dst=MAC1o, src=MAC1i) / IntSight(epoch=42, path_src=23, path_length=1, path_code=1, contention_points=0b1, e2e_delay=0xaa0, ingress_packets=cPktCnt, ingress_bytes=cPktCnt*64, next_header=0)
    pkt = pad_pkt(pkt, 82)
    expPkt(pkt, 'nf1')

def test_intsight_removal():
    global pktCnt
    global rPktCnt
    rPktCnt += 1
    pkt = Ether(dst=MAC2i, src=MAC2o) / IntSight(epoch=42, path_src=23, path_length=2, path_code=1, contention_points=0b10, e2e_delay=0xaa0, ingress_packets=rPktCnt, ingress_bytes=rPktCnt*64, next_header=0)
    pkt = pad_pkt(pkt, 82)
    applyPkt(pkt, 'nf2', pktCnt)
    pktCnt += 1
    pkt = Ether(dst=MAC3o, src=MAC3i)
    pkt = pad_pkt(pkt, 64)
    expPkt(pkt, 'nf3')

def test_intsight_digest():
    global pktCnt
    pkt = Ether(dst=MAC2i, src=MAC2o) / IntSight(epoch=43, path_src=23, path_length=2, path_code=1, contention_points=0b10, e2e_delay=0xaa0, ingress_packets=1, ingress_bytes=64, next_header=0)
    pkt = pad_pkt(pkt, 82)
    applyPkt(pkt, 'nf2', pktCnt)
    pktCnt += 1
    pkt = Ether(dst=MAC3o, src=MAC3i)
    pkt = pad_pkt(pkt, 64)
    digest = {
        'epoch': 42,
        'flow_ID': 3,
        'path_src': 23,
        'path_length': 3,
        'path_code': 1,
        'path_dst': 23,
        'contention_points': 0b110,
        'high_delays': 5,
        'rxpkts': 5,
        'rxbytes': 5*64,
        'txpkts': 5,
        'txbytes': 5*64,
        'drops': 0,
        'unused': 0
    }
    expPkt(pkt, 'nf3', digest=digest)

for i in range(5):
    # op1 = random.randint(0,2**31) 
    # op2 = random.randint(0,2**31) 
    # while op1 < op2:
    #     op2 = random.randint(0,2**31) 
    # test_add(op1, op2)
    # test_sub(op1, op2)
    # test_lookup(op1)
    # test_reg(op1, op2)
    test_intsight_modification()
    test_intsight_creation()
    test_intsight_removal()

test_intsight_digest()

write_pcap_files()

