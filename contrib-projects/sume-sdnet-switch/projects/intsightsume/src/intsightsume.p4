//
// Copyright (c) 2020 Jonatas Adilson Marques
// All rights reserved.
//
// This software was developed by Stanford University and the University of Cambridge Computer Laboratory 
// under National Science Foundation under Grant No. CNS-0855268,
// the University of Cambridge Computer Laboratory under EPSRC INTERNET Project EP/H040536/1 and
// by the University of Cambridge Computer Laboratory under DARPA/AFRL contract FA8750-11-C-0249 ("MRC2"), 
// as part of the DARPA MRC research programme.
//
// @NETFPGA_LICENSE_HEADER_START@
//
// Licensed to NetFPGA C.I.C. (NetFPGA) under one or more contributor
// license agreements.  See the NOTICE file distributed with this work for
// additional information regarding copyright ownership.  NetFPGA licenses this
// file to you under the NetFPGA Hardware-Software License, Version 1.0 (the
// "License"); you may not use this file except in compliance with the
// License.  You may obtain a copy of the License at:
//
//   http://www.netfpga-cic.org
//
// Unless required by applicable law or agreed to in writing, Work distributed
// under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
// CONDITIONS OF ANY KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations under the License.
//
// @NETFPGA_LICENSE_HEADER_END@
//


#include <core.p4>
#include <sume_switch.p4>

typedef bit<48> EthAddr_t; 
// #define CALC_TYPE     0x1212
#define INTSIGHT_TYPE 0x1213
#define INDEX_WIDTH 10
typedef bit<8> flow_ID_t;
typedef bit<8> node_ID_t;
// typedef bit<32> calcField_t;
#define MAX_LATENCY 1024

#define REG_READ 8w0
#define REG_WRITE 8w1
#define REG_ADD  8w2
#define REG_BOR  8w2

#define EQ_RELOP    8w0
#define NEQ_RELOP   8w1
#define GT_RELOP    8w2
#define LT_RELOP    8w3


// #define REG_READ 8w0
// #define REG_WRITE 8w1

// #define INDEX_WIDTH 4 // determines depth of const register

// const register
// @Xilinx_MaxLatency(64)
// @Xilinx_ControlWidth(INDEX_WIDTH)
// extern void const_reg_rw(in bit<INDEX_WIDTH> index, 
//                          in calcField_t newVal, 
//                          in bit<8> opCode, 
//                          out calcField_t result);

// Extern: Ingress Timestamp
@Xilinx_MaxLatency(MAX_LATENCY)
@Xilinx_ControlWidth(0)
extern void epoch_timestamp(in bit<1> valid, out bit<32> result);

// Register: Ingress Epoch
@Xilinx_MaxLatency(MAX_LATENCY)
@Xilinx_ControlWidth(INDEX_WIDTH)
extern void iepoch_reg_praw(in  bit<INDEX_WIDTH> index,
                            in  bit<32>   newVal,
                            in  bit<32>   incVal,
                            in  bit<8>    opCode,
                            in  bit<32>   compVal,
                            in  bit<8>    relOp,
                            out bit<32>   result,
                            out bit<1>    boolean);

// Register: Ingress Group 1 - Received Packets and Received Bytes
@Xilinx_MaxLatency(MAX_LATENCY)
@Xilinx_ControlWidth(INDEX_WIDTH)
extern void igroup1_reg_raw(in  bit<INDEX_WIDTH> index,
                            in  bit<64>   newVal,
                            in  bit<64>   incVal,
                            in  bit<8>    opCode,
                            out bit<64>   result);

// Register: Egress Bit Flip per Packet
@Xilinx_MaxLatency(MAX_LATENCY)
@Xilinx_ControlWidth(INDEX_WIDTH)
extern void ebfpkt_reg_ifElseRaw(in  bit<INDEX_WIDTH> index_2,
                                 in  bit<1>    newVal_2,
                                 in  bit<1>    incVal_2,
                                 in  bit<8>    opCode_2,
                                 in  bit<INDEX_WIDTH> index_1,
                                 in  bit<1>    newVal_1,
                                 in  bit<1>    incVal_1,
                                 in  bit<8>    opCode_1,
                                 in  bit<INDEX_WIDTH> index_comp,
                                 in  bit<1>    compVal,
                                 in  bit<8>    relOp,
                                 out bit<1>    result,
                                 out bit<1>    boolean);

// Register: Egress Epoch
@Xilinx_MaxLatency(MAX_LATENCY)
@Xilinx_ControlWidth(INDEX_WIDTH)
extern void eepoch_a_reg_rw(in  bit<INDEX_WIDTH> index,
                            in  bit<32>   newVal,
                            in  bit<8>    opCode,
                            out bit<32>   result);
@Xilinx_MaxLatency(MAX_LATENCY)
@Xilinx_ControlWidth(INDEX_WIDTH)
extern void eepoch_b_reg_rw(in  bit<INDEX_WIDTH> index,
                            in  bit<32>   newVal,
                            in  bit<8>    opCode,
                            out bit<32>   result);

// Register: Egress Bit Flip per Epoch
@Xilinx_MaxLatency(MAX_LATENCY)
@Xilinx_ControlWidth(INDEX_WIDTH)
extern void ebfepoch_reg_ifElseRaw(in  bit<INDEX_WIDTH> index_2,
                                   in  bit<1>    newVal_2,
                                   in  bit<1>    incVal_2,
                                   in  bit<8>    opCode_2,
                                   in  bit<INDEX_WIDTH> index_1,
                                   in  bit<1>    newVal_1,
                                   in  bit<1>    incVal_1,
                                   in  bit<8>    opCode_1,
                                   in  bit<INDEX_WIDTH> index_comp,
                                   in  bit<1>    compVal,
                                   in  bit<8>    relOp,
                                   out bit<1>    result,
                                   out bit<1>    boolean);

// Register: Egress Group 1 (Path Source, Path Length, Path Code,
//                           Ingress Packets, and Ingress Bytes)
@Xilinx_MaxLatency(MAX_LATENCY)
@Xilinx_ControlWidth(INDEX_WIDTH)
extern void egroup1_a_reg_rw(in  bit<INDEX_WIDTH> index,
                             in  bit<56>  newVal,
                             in  bit<8>   opCode,
                             out bit<56>  result);
@Xilinx_MaxLatency(MAX_LATENCY)
@Xilinx_ControlWidth(INDEX_WIDTH)
extern void egroup1_b_reg_rw(in  bit<INDEX_WIDTH> index,
                             in  bit<56>   newVal,
                             in  bit<8>    opCode,
                             out bit<56>   result);

// Register: Egress Group 2 (Number of High Delays, Egress Packets,
//                           and Egress Bytes)
@Xilinx_MaxLatency(MAX_LATENCY)
@Xilinx_ControlWidth(INDEX_WIDTH)
extern void egroup2_a_reg_raw(in  bit<INDEX_WIDTH> index,
                              in  bit<48>   newVal,
                              in  bit<48>   incVal,
                              in  bit<8>    opCode,
                              out bit<48>   result);
@Xilinx_MaxLatency(MAX_LATENCY)
@Xilinx_ControlWidth(INDEX_WIDTH)
extern void egroup2_b_reg_raw(in  bit<INDEX_WIDTH> index,
                              in  bit<48>   newVal,
                              in  bit<48>   incVal,
                              in  bit<8>    opCode,
                              out bit<48>   result);

// Register: Egress Contention Points
@Xilinx_MaxLatency(MAX_LATENCY)
@Xilinx_ControlWidth(INDEX_WIDTH)
extern void ecps_a_reg_rbow(in  bit<INDEX_WIDTH> index,
                            in  bit<8>    newVal,
                            in  bit<8>    incVal,
                            in  bit<8>    opCode,
                            out bit<8>    result);
@Xilinx_MaxLatency(MAX_LATENCY)
@Xilinx_ControlWidth(INDEX_WIDTH)
extern void ecps_b_reg_rbow(in  bit<INDEX_WIDTH> index,
                            in  bit<8>    newVal,
                            in  bit<8>    incVal,
                            in  bit<8>    opCode,
                            out bit<8>    result);

// standard Ethernet header
header Ethernet_h { 
    EthAddr_t dstAddr; 
    EthAddr_t srcAddr; 
    bit<16> etherType;
}

header IntSight_h {
    bit<32> epoch;
    bit<8>  path_src;
    bit<8>  path_length;
    bit<8>  path_code;
    bit<8>  contention_points;
    bit<16> e2e_delay;
    bit<16> ingress_packets;
    bit<16> ingress_bytes;
    bit<32> next_header;
}

// List of all recognized headers
struct Parsed_packet { 
    Ethernet_h ethernet; 
    IntSight_h intsight;
}

// user defined metadata: can be used to share information between
// TopParser, TopPipe, and TopDeparser 
struct user_metadata_t {
    bit<1> is_ingress_node;
    bit<1> is_egress_node;
    flow_ID_t flow_ID;
    node_ID_t node_ID;
    // INGRESS
    bit<32> iepoch;
    bit<1>  inewepoch;
    bit<32> irxpkts;
    bit<32> irxbytes;
    // ALL
    bit<16> adst_q_size;
    bit<16> aqueue_delay;
    bit<16> aqt_depth;
    // EGRESS
    bit<1>  ehighlydelayed;
    bit<1>  ebfpkt;
    bit<32> eepoch;
    bit<1>  enewepoch;
    bit<1>  ebfepoch;
    bit<56> egroup1;
    bit<8>  epathsrc; // in group 1
    bit<8>  epathlen; // in group 1
    bit<8>  epathcode; // in group 1
    bit<16> erxpkts; // in group 1
    bit<16> erxbytes; // in group 1
    bit<48> egroup2;
    bit<16> ehighdelays; // in group 2
    bit<16> etxpkts; // in group 2
    bit<16> etxbytes; // in group 2
    bit<8>  ecps;
    bit<1>  egenreport;
    bit<4>  eslos;
    bit<32> threshold1;
    bit<32> threshold2;
    bit<16> ee2edelay_threshold;
    bit<16> ebandwidth_threshold;
    bit<16> edrops;
}

// digest_data, MUST be 256 bits
struct digest_data_t {
    bit<80>    unused;
    bit<16>    drops;
    bit<16>    txbytes;
    bit<16>    txpkts;
    bit<16>    rxbytes;
    bit<16>    rxpkts;
    bit<16>    high_delays;
    bit<8>     contention_points;
    node_ID_t  path_dst;
    bit<8>     path_code;
    bit<8>     path_length;
    node_ID_t  path_src;
    flow_ID_t  flow_ID;
    bit<32>    epoch;
}

// Parser Implementation
@Xilinx_MaxPacketRegion(1024)
parser TopParser(packet_in b, 
                 out Parsed_packet p, 
                 out user_metadata_t user_metadata,
                 out digest_data_t digest_data,
                 inout sume_metadata_t sume_metadata) {
    state start {
        b.extract(p.ethernet);
        // General processing
        user_metadata.node_ID = 23;
        user_metadata.flow_ID = 0;
        user_metadata.is_ingress_node = 0;
        user_metadata.is_egress_node = 0;
        // Ingress processing
        user_metadata.iepoch = 0;
        user_metadata.inewepoch = 0;
        user_metadata.irxpkts = 0;
        user_metadata.irxbytes = 0;
        // Ingress processing
        user_metadata.iepoch = 42;
        user_metadata.inewepoch = 0;
        // Path processing
        user_metadata.adst_q_size = 0;
        user_metadata.aqueue_delay = 0;
        user_metadata.aqt_depth = 0;
        // Egress processing
        user_metadata.ehighlydelayed = 0;
        user_metadata.ebfpkt = 0;
        user_metadata.eepoch = 0;
        user_metadata.enewepoch = 0;
        user_metadata.ebfepoch = 0;
        user_metadata.egroup1 = 0;
        user_metadata.epathsrc = 0;
        user_metadata.epathlen = 0;
        user_metadata.epathcode = 0;
        user_metadata.erxpkts = 0;
        user_metadata.erxbytes = 0;
        user_metadata.egroup2 = 0;
        user_metadata.ehighdelays = 0;
        user_metadata.etxpkts = 0;
        user_metadata.etxbytes = 0;
        user_metadata.ecps = 0;
        user_metadata.egenreport = 0;
        user_metadata.eslos = 0;
        user_metadata.threshold1 = 0;
        user_metadata.threshold2 = 0;
        user_metadata.ee2edelay_threshold = 0;
        user_metadata.ebandwidth_threshold = 0;
        user_metadata.edrops = 0;
        // Digest data
        digest_data.epoch = 0;
        digest_data.flow_ID = 0;
        digest_data.path_src = 0;
        digest_data.path_length = 0;
        digest_data.path_code = 0;
        digest_data.path_dst = 0;
        digest_data.contention_points = 0;
        digest_data.high_delays = 0;
        digest_data.rxpkts = 0;
        digest_data.rxbytes = 0;
        digest_data.txpkts = 0;
        digest_data.txbytes = 0;
        digest_data.drops = 0;
        digest_data.unused = 0;

        transition select(p.ethernet.etherType) {
            // CALC_TYPE: parse_calc;
            INTSIGHT_TYPE: parse_intsight;
            default: reject;
        } 
    }

    // state parse_calc { 
    //     b.extract(p.calc);
    //     transition accept; 
    // }

    state parse_intsight {
        b.extract(p.intsight);
        transition accept;
    }
}

// match-action pipeline
control TopPipe(inout Parsed_packet p,
                inout user_metadata_t user_metadata, 
                inout digest_data_t digest_data,
                inout sume_metadata_t sume_metadata) {
 
    // action set_result(calcField_t data) {
    //     p.calc.result = data;
    // }

    // action set_result_default() {
    //     p.calc.result = 32w0;
    // }

    // table lookup_table {
    //     key = { p.calc.op1: exact; }

    //     actions = {
    //         set_result;
    //         set_result_default;
    //     }
    //     size = 64;
    //     default_action = set_result_default;
    // }

    action set_flow_ID(flow_ID_t flow_ID) {
        user_metadata.flow_ID = flow_ID;
    }

    table tab_flow_ID {
        key = {
            p.ethernet.srcAddr: exact;
            // p.ethernet.dstAddr: exact;
        }
        actions = {
            NoAction;
            set_flow_ID;
        }
        // size = 512;
        default_action = NoAction(); // set_flow_ID(0)
    }

    action set_queue_delay(bit<16> queue_delay) {
        user_metadata.aqueue_delay = queue_delay;
    }

    table tab_queue_delay {
        key = {
            user_metadata.adst_q_size: exact;
        }
        actions = {
            NoAction;
            set_queue_delay;
        }
        // size = 128;
        default_action = NoAction();
    }

    action set_path_ID(bit<8> new_path_code) {
        p.intsight.path_code = new_path_code;
    }

    table tab_update_path_ID {
        key = {
            p.intsight.path_src: exact;
            p.intsight.path_length: exact;
            p.intsight.path_code: exact;
            sume_metadata.dst_port: exact;
        }
        actions = {
            NoAction;
            set_path_ID;
        }
        // size = 128;
        default_action = NoAction();
    }

    action set_slo_threshold(bit<4> slos, bit<32> t1, bit<32> t2) {
        user_metadata.eslos = slos;
        user_metadata.threshold1 = t1;
        user_metadata.threshold2 = t2;
    }

    table tab_slo_threshold {
        key = {
            user_metadata.flow_ID: exact;
        }
        actions = {
            NoAction;
            set_slo_threshold;
        }
        // size = 128;
        default_action = NoAction();
    }

    apply {
        // bounce packet back to sender
        // swap_eth_addresses();
        // set_output_port();

        tab_flow_ID.apply();

        // Forwarding decision
        if(sume_metadata.src_port == 0b00000001) {
            sume_metadata.dst_port = 0b00000100;
            p.ethernet.srcAddr = 0x00183E020DA1;
            p.ethernet.dstAddr = 0x000000000200;
        } else if(sume_metadata.src_port == 0b00000100) {
            sume_metadata.dst_port = 0b00010000;
            p.ethernet.srcAddr = 0x00183E020DA2;
            p.ethernet.dstAddr = 0x000000000300;
        } else if(sume_metadata.src_port == 0b00010000) {
            sume_metadata.dst_port = 0b01000000;
            p.ethernet.srcAddr = 0x00183E020DA3;
            p.ethernet.dstAddr = 0x000000000400;
        } else if(sume_metadata.src_port == 0b01000000) {
            sume_metadata.dst_port = 0b00000001;
            p.ethernet.srcAddr = 0x00183E020DA0;
            p.ethernet.dstAddr = 0x000000000100;
        }

        // Is this node the ingress node for the packet?
        if(sume_metadata.src_port == 0b00000001) {
            user_metadata.is_ingress_node = 1;
        }
        // Is this node the egress node for the packet?
        if(sume_metadata.dst_port == 0b01000000) {
            user_metadata.is_egress_node = 1;
        }

        // if (p.calc.isValid()) {
        //     // based on the opCode, set the result or state appropriately
        //     if (p.calc.opCode == ADD_OP) {
        //         // TODO: addition
        //         p.calc.result = p.calc.op1 + p.calc.op2;
        //     } else if (p.calc.opCode == SUB_OP) {
        //         // TODO: subtraction
        //         p.calc.result = p.calc.op1 - p.calc.op2;
        //     } else if (p.calc.opCode == LOOKUP_OP) {
        //         // TODO: Key-Value lookup
        //         lookup_table.apply(); 
        //     } else if (p.calc.opCode == ADD_REG_OP || p.calc.opCode == SET_REG_OP) {
        //         // Read or write register
    
        //         // Pre-register access: define metadata
        //         bit<INDEX_WIDTH> index = p.calc.op1[INDEX_WIDTH-1:0];
        //         calcField_t newVal;
        //         bit<8> opCode;
        //         calcField_t regVal;
                
        //         // Pre-register access: set metadata appropriately
        //         if (p.calc.opCode == ADD_REG_OP) {
        //             newVal = 0;
        //             opCode = REG_READ;
        //         } else {
        //             newVal = p.calc.op2;
        //             opCode = REG_WRITE;
        //         }

        //         // Register access!
        //         const_reg_rw(index, newVal, opCode, regVal);

        //         // set result for ADD_REG operation
        //         if (p.calc.opCode == ADD_REG_OP) {
        //             p.calc.result = p.calc.op2 + regVal;
        //         }
        //     }
        // }

        ///////////////////////////////////////////////////////////
        ////////          INGRESS NODE PROCESSING          ////////
        ///////////////////////////////////////////////////////////
        if(user_metadata.is_ingress_node == 1) {
            // Get current epoch
            bit<32> timestamp;
            epoch_timestamp(1, timestamp);
            user_metadata.iepoch = (bit<32>) timestamp;
            user_metadata.iepoch = 42; // Use fixed epoch for testing purposes

            // UPDATE FLOW REGISTERS
            // Register: Epoch
            iepoch_reg_praw(((bit<INDEX_WIDTH>) user_metadata.flow_ID), // index
                            user_metadata.iepoch, // newVal
                            0, // incVal - never used
                            REG_WRITE, // opCode
                            user_metadata.iepoch, // compVal
                            NEQ_RELOP, // relOp
                            user_metadata.iepoch, // result
                            user_metadata.inewepoch); // predicate result
            
            // Register Group i1: Received packets and received bytes
            bit<8> opCode_igroup1;
            if(user_metadata.inewepoch == 1) {
                opCode_igroup1 = REG_WRITE;
            } else {
                opCode_igroup1 = REG_ADD;
            }
            bit<64> val_igroup1 = (1<<32) | ((bit<64>) sume_metadata.pkt_len);
            bit<64> result_igroup1;
            igroup1_reg_raw(((bit<INDEX_WIDTH>) user_metadata.flow_ID), // index
                            val_igroup1, // newVal
                            val_igroup1, // incVal
                            opCode_igroup1, // opCode
                            result_igroup1); // result
            
            user_metadata.irxpkts = (bit<32>) (result_igroup1 >> 32);
            user_metadata.irxbytes = (bit<32>) (((1<<32) - 1) & result_igroup1);

            // CREATE TELEMETRY HEADER
            p.intsight.setValid();
            p.intsight.epoch = user_metadata.iepoch;
            p.intsight.path_src = user_metadata.node_ID;
            p.intsight.path_length = 0;
            p.intsight.path_code = 1;
            p.intsight.contention_points = 0;
            p.intsight.e2e_delay = 0xa00;
            p.intsight.ingress_packets = (bit<16>) user_metadata.irxpkts;
            p.intsight.ingress_bytes = (bit<16>) user_metadata.irxbytes;
            p.intsight.next_header = (bit<32>) p.ethernet.etherType;

            p.ethernet.etherType = INTSIGHT_TYPE;
        }

        ////////////////////////////////////////////////////////////////
        ////////             PROCESSING ON ALL NODES            ////////
        ////////////////////////////////////////////////////////////////
        if(p.intsight.isValid()) {
            // INCREMENT FIELD: END-TO-END DELAY
            user_metadata.adst_q_size = 0;
            if((sume_metadata.dst_port & 1) > 0) {
                user_metadata.adst_q_size = sume_metadata.nf0_q_size >> 5;
            } else if((sume_metadata.dst_port & (1<<2)) > 0) {
                user_metadata.adst_q_size = sume_metadata.nf1_q_size >> 5;
            } else if((sume_metadata.dst_port & (1<<4)) > 0) {
                user_metadata.adst_q_size = sume_metadata.nf2_q_size >> 5;
            } else if((sume_metadata.dst_port & (1<<6)) > 0) {
                user_metadata.adst_q_size = sume_metadata.nf3_q_size >> 5;
            }
            // Queueing Delay = (dst_q_size >> 5) * 0.8192 microseconds
            // dst_qsize >> 5 in [0, 2048) in integers
            tab_queue_delay.apply();
            p.intsight.e2e_delay = p.intsight.e2e_delay
                                       + 0x0a0 // FIXED PROCESSING DELAY
                                       + user_metadata.aqueue_delay;

            // CONTENTION?
            // tab_contention_thresholds.apply();
            user_metadata.aqt_depth = 0;  // fixed value for testing purposes
            if((((sume_metadata.dst_port & 1) > 0)
                    && (sume_metadata.nf0_q_size >= user_metadata.aqt_depth))
                || (((sume_metadata.dst_port & (1<<2)) > 0)
                    && (sume_metadata.nf1_q_size >= user_metadata.aqt_depth))
                || (((sume_metadata.dst_port & (1<<4)) > 0)
                    && (sume_metadata.nf2_q_size >= user_metadata.aqt_depth))
                || (((sume_metadata.dst_port & (1<<6)) > 0)
                    && (sume_metadata.nf3_q_size >= user_metadata.aqt_depth))) {
                // MARK FIELD: CONTENTION POINTS
                p.intsight.contention_points = \
                    p.intsight.contention_points
                    | ((bit<8>) 1<<p.intsight.path_length);
            }
            
            // UPDATE FIELD: PATH ID
            tab_update_path_ID.apply();
            p.intsight.path_length = p.intsight.path_length + 1;
        }

        ////////////////////////////////////////////////////////////////
        ////////             EGRESS NODE PROCESSING             ////////
        ////////////////////////////////////////////////////////////////
        if(user_metadata.is_egress_node == 1) {
            // INCREMENT FIELD: END-TO-END DELAY
            //                  WITH FIXED EGRESS PROCESSING DELAY
            p.intsight.e2e_delay = p.intsight.e2e_delay + 0x00a;

            // GET SLOS (THRESHOLDS) ASSOCIATED TO THE FLOW
            tab_slo_threshold.apply();
            if(user_metadata.eslos == 1) {
                user_metadata.ee2edelay_threshold = (bit<16>) user_metadata.threshold1;
            } else if(user_metadata.eslos == 2) {
                user_metadata.ebandwidth_threshold = (bit<16>) user_metadata.threshold1;
            } else if(user_metadata.eslos == 3) {
                user_metadata.ee2edelay_threshold = (bit<16>) user_metadata.threshold1;
                user_metadata.ebandwidth_threshold = (bit<16>) user_metadata.threshold2;
            }
            
            // CHECK IF THE END-TO-END DELAY WAS TOO HIGH
            if(((user_metadata.eslos & 0b1) > 0)
               && (p.intsight.e2e_delay > user_metadata.ee2edelay_threshold)) {
            // if((p.intsight.e2e_delay > 0xa00) {
                user_metadata.ehighlydelayed = 1;
            } else {
                user_metadata.ehighlydelayed = 0;
            }

            // ================
            // UPDATE REGISTERS
            // ================

            // REGISTER: EGRESS BIT FLIP PER PACKET
            bit<1> pResult_ebfpkt;
            ebfpkt_reg_ifElseRaw(
                ((bit<INDEX_WIDTH>) user_metadata.flow_ID), // index_2
                0, // newVal_2
                0, // incVal_2 - not used
                REG_WRITE, // opCode_2
                ((bit<INDEX_WIDTH>) user_metadata.flow_ID), // index_1
                1, // newVal_1
                0, // incVal_1 - not used
                REG_WRITE, // opCode_1
                ((bit<INDEX_WIDTH>) user_metadata.flow_ID), // index_comp
                0, // compVal
                EQ_RELOP, // relOp
                user_metadata.ebfpkt, // result
                pResult_ebfpkt // boolean - ignored
            );

            // REGISTER: EGRESS EPOCH
            bit<8> opCode_eepoch_a;
            bit<8> opCode_eepoch_b;
            if(user_metadata.ebfpkt == 0) {
                opCode_eepoch_a = REG_READ;
                opCode_eepoch_b = REG_WRITE;
            } else {
                opCode_eepoch_a = REG_WRITE;
                opCode_eepoch_b = REG_READ;
            }
            bit<32> eepoch_a;
            bit<32> eepoch_b;
            eepoch_a_reg_rw(
                ((bit<INDEX_WIDTH>) user_metadata.flow_ID), // index
                p.intsight.epoch, // newVal
                opCode_eepoch_a, // opCode
                eepoch_a // result
            );
            eepoch_b_reg_rw(
                ((bit<INDEX_WIDTH>) user_metadata.flow_ID), // index
                p.intsight.epoch, // newVal
                opCode_eepoch_b, // opCode
                eepoch_b // result
            );
            if(user_metadata.ebfpkt == 0) {
                user_metadata.eepoch = eepoch_a;
            } else {
                user_metadata.eepoch = eepoch_b;
            }

            // CHECK IF THIS IS A PACKET FROM A NEW EPOCH
            if(user_metadata.eepoch != p.intsight.epoch) {
                user_metadata.enewepoch = 1;
            } else {
                user_metadata.enewepoch = 0;
            }

            // REGISTER: EGRESS BIT FLIP PER EPOCH
            bit<8> opCode_ebfepoch;
            bit<1> pResult_ebfepoch; // ignored
            if(user_metadata.enewepoch == 1) {
                opCode_ebfepoch = REG_WRITE;
            } else {
                opCode_ebfepoch = REG_READ;
            }
            ebfepoch_reg_ifElseRaw(
                ((bit<INDEX_WIDTH>) user_metadata.flow_ID), // index_2
                0, // newVal_2
                0, // incVal_2 - not used
                opCode_ebfepoch, // opCode_2
                ((bit<INDEX_WIDTH>) user_metadata.flow_ID), // index_1
                1, // newVal_1
                0, // incVal_1 - not used
                opCode_ebfepoch, // opCode_1
                ((bit<INDEX_WIDTH>) user_metadata.flow_ID), // index_comp
                0, // compVal
                EQ_RELOP, // relOp
                user_metadata.ebfepoch, // result
                pResult_ebfepoch // boolean
            );

            // REGISTER: EGRESS GROUP 1 (PATH SRC, PATH LENGTH, PATH CODE,
            //                           INGRESS PACKETS, AND INGRESS BYTES)
            bit<8> opCode_egroup1_a;
            bit<8> opCode_egroup1_b;
            if(user_metadata.ebfepoch == 0) {
                opCode_egroup1_a = REG_READ;
                opCode_egroup1_b = REG_WRITE;
            } else {
                opCode_egroup1_a = REG_WRITE;
                opCode_egroup1_b = REG_READ;
            }
            bit<56> egroup1_a =
                  (((bit<56>) p.intsight.path_src       ) << 48)
                | (((bit<56>) p.intsight.path_length    ) << 40)
                | (((bit<56>) p.intsight.path_code      ) << 32)
                | (((bit<56>) p.intsight.ingress_packets) << 16)
                | (((bit<56>) p.intsight.ingress_bytes  )      );
            bit<56> egroup1_b = egroup1_a;
            egroup1_a_reg_rw(((bit<INDEX_WIDTH>) user_metadata.flow_ID), // index
                             egroup1_a, // newVal
                             opCode_egroup1_a, // opCode
                             egroup1_a); // result
            egroup1_b_reg_rw(((bit<INDEX_WIDTH>) user_metadata.flow_ID), // index
                             egroup1_b, // newVal
                             opCode_egroup1_b, // opCode
                             egroup1_b); // result
            if(user_metadata.ebfepoch == 0) {
                user_metadata.egroup1 = egroup1_a;
            } else {
                user_metadata.egroup1 = egroup1_b;
            }
            user_metadata.epathsrc  = (bit<8>)  (((1<<8)  - 1) & (user_metadata.egroup1 >> 48));
            user_metadata.epathlen  = (bit<8>)  (((1<<8)  - 1) & (user_metadata.egroup1 >> 40));
            user_metadata.epathcode = (bit<8>)  (((1<<8)  - 1) & (user_metadata.egroup1 >> 32));
            user_metadata.erxpkts   = (bit<16>) (((1<<16) - 1) & (user_metadata.egroup1 >> 16));
            user_metadata.erxbytes  = (bit<16>) (((1<<16) - 1) & (user_metadata.egroup1      ));

            // REGISTER: EGRESS GROUP 2 (NUMBER OF HIGH DELAYS, EGRESS PACKETS,
            //                           AND EGRESS BYTES)
            bit<8> opCode_egroup2_a;
            bit<8> opCode_egroup2_b;
            if(user_metadata.ebfepoch == 0) {
                opCode_egroup2_a = REG_READ;
                if(user_metadata.enewepoch == 1) {
                    opCode_egroup2_b = REG_WRITE;
                } else {
                    opCode_egroup2_b = REG_ADD;
                }
            } else {
                if(user_metadata.enewepoch == 1) {
                    opCode_egroup2_a = REG_WRITE;
                } else {
                    opCode_egroup2_a = REG_ADD;
                }
                opCode_egroup2_b = REG_READ;
            }
            bit<48> egroup2_a =
                  (((bit<48>) user_metadata.ehighlydelayed        ) << 32)
                | (((bit<48>) 1                         ) << 16)
                | (((bit<48>) sume_metadata.pkt_len - 18)      );
            bit<48> egroup2_b = egroup2_a;
            egroup2_a_reg_raw(((bit<INDEX_WIDTH>) user_metadata.flow_ID), // index
                              egroup2_a, // newVal
                              egroup2_a, // incVal
                              opCode_egroup2_a, // opCode
                              egroup2_a); // result
            egroup2_b_reg_raw(((bit<INDEX_WIDTH>) user_metadata.flow_ID), // index
                              egroup2_b, // newVal
                              egroup2_b, // incVal
                              opCode_egroup2_b, // opCode
                              egroup2_b); // result
            if(user_metadata.ebfepoch == 0) {
                user_metadata.egroup2 = egroup2_a;
            } else {
                user_metadata.egroup2 = egroup2_b;
            }
            user_metadata.ehighdelays = (bit<16>) (((1<<16) - 1) & (user_metadata.egroup2 >> 32));
            user_metadata.etxpkts     = (bit<16>) (((1<<16) - 1) & (user_metadata.egroup2 >> 16));
            user_metadata.etxbytes    = (bit<16>) (((1<<16) - 1) & (user_metadata.egroup2    ));

            // REGISTERS: CONTENTION POINTS
            bit<8> opCode_ecps_a;
            bit<8> opCode_ecps_b;
            if(user_metadata.ebfepoch == 0) {
                opCode_ecps_a = REG_READ;
                if(user_metadata.enewepoch == 1) {
                    opCode_ecps_b = REG_WRITE;
                } else {
                    opCode_ecps_b = REG_BOR;
                }
            } else {
                if(user_metadata.enewepoch == 1) {
                    opCode_ecps_a = REG_WRITE;
                } else {
                    opCode_ecps_a = REG_BOR;
                }
                opCode_ecps_b = REG_READ;
            }
            bit<8> ecps_a;
            bit<8> ecps_b;
            ecps_a_reg_rbow(((bit<INDEX_WIDTH>) user_metadata.flow_ID),
                            p.intsight.contention_points,
                            p.intsight.contention_points,
                            opCode_ecps_a,
                            ecps_a);
            ecps_b_reg_rbow(((bit<INDEX_WIDTH>) user_metadata.flow_ID),
                            p.intsight.contention_points,
                            p.intsight.contention_points,
                            opCode_ecps_b,
                            ecps_b);
            if(user_metadata.ebfepoch == 0) {
                user_metadata.ecps = ecps_a;
            } else {
                user_metadata.ecps = ecps_b;
            }
            // ========================
            // END OF REGISTER UPDATING
            // ========================

            // DOES A REPORT NEED TO BE GENERATED?
            if((user_metadata.enewepoch == 1) && (user_metadata.eepoch > 0)) {
            // if(user_metadata.enewepoch == 1) {
                user_metadata.egenreport = 1;  // testing, always report upon new epoch

                if(user_metadata.ehighdelays > 0) {
                    user_metadata.egenreport = 1;
                }

                user_metadata.edrops = user_metadata.erxpkts - user_metadata.etxpkts;
                if(((user_metadata.eslos & 0b10) > 0)
                   && (user_metadata.etxbytes < user_metadata.ebandwidth_threshold)
                   && (user_metadata.edrops > 0)) {
                    user_metadata.egenreport = 1;
                }

                if(user_metadata.ecps > 0) {
                    user_metadata.egenreport = 1;
                }
            }

            // GENERATE REPORT
            // user_metadata.egenreport = 1;  // testing, always report upon new packet
            if(user_metadata.egenreport == 1) {
                digest_data.epoch = user_metadata.eepoch;
                digest_data.flow_ID = user_metadata.flow_ID;
                digest_data.path_src = user_metadata.epathsrc;
                digest_data.path_length = user_metadata.epathlen;
                digest_data.path_code = user_metadata.epathcode;
                digest_data.path_dst = user_metadata.node_ID;
                digest_data.contention_points = user_metadata.ecps;
                digest_data.high_delays = user_metadata.ehighdelays;
                digest_data.rxpkts = user_metadata.erxpkts;
                digest_data.rxbytes = user_metadata.erxbytes;
                digest_data.txpkts = user_metadata.etxpkts;
                digest_data.txbytes = user_metadata.etxbytes;
                digest_data.drops = user_metadata.edrops;

                sume_metadata.send_dig_to_cpu = 1;
            }

            // REMOVE TELEMETRY HEADER FROM PACKET
            p.ethernet.etherType = (bit<16>) p.intsight.next_header;
            p.intsight.setInvalid();
        }

    }
}

// Deparser Implementation
@Xilinx_MaxPacketRegion(1024)
control TopDeparser(packet_out b,
                    in Parsed_packet p,
                    in user_metadata_t user_metadata,
                    inout digest_data_t digest_data,
                    inout sume_metadata_t sume_metadata) { 
    apply {
        b.emit(p.ethernet); 
        // b.emit(p.calc);
        b.emit(p.intsight);
    }
}


// Instantiate the switch
SimpleSumeSwitch(TopParser(), TopPipe(), TopDeparser()) main;
