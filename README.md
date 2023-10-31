# Inband Network Telemetry (INT) in the scope of Load Balancing

## Introduction

This Repository was created to develop and store an Inband Network Telemetry (INT) implementation to explore its capabilities and outcomes in the scope of load balancing. 

The Network was deployed based on a P4 Tutorial available on https://github.com/p4lang/tutorials/tree/master. 

All the necessary software can be obtained by downloading the recommended Virtual Machine or by following the provided instructions and scripts (only for Ubuntu 20.04 or 22.04 Linux System). This tutorial was utilized as a starting point, as it provides some exercises regarding P4 functionalities and implementations. 

The first step for presenting this implementation was to understand and learn from the provided use cases and adapt the necessary P4 code, as well as the topology file `topology.json`. 

The Inband Network Telemetry environment was deployed using Mininet. 

The network architecture is presented in Figure 3.1.

<p align="center"><img src="Pictures/Network Architecture.png" width="650"></p>

This System implements INT-MD as INT Application Type, where S1 is the INT Source Node, S2, S3 and S4 are Transit Hops and S5 acts as the Sink Node. These functions are assigned by the Controller `controller.py`.

Within this architecture, there are two possible paths (represented with distinct colors) for the traffic generated in Host 1 towards Host 2, them being H1-S1-S2-S3-S5-H2 and H1-S1-S2-S4-S5-H2. 

S2 will be responsible for implementing the Load Balancing logic.

S6 will mirror the INT packets with the latency values and forward them back to S2, that will make the best-path decision based on the lower latency value.

To enhance this proccess, a new TCP option was defined, with the following format:


<p align="center"><img src="Pictures/TCP_Option_Format.png" width="400"></p>


  * Kind (8b): Tcp Option Kind, 0x73, reserved at the moment.

  * Length (8b): Length of the Options Field, 12 Bytes.

  * Path  (16b): Path traversed by the packets.

  * Total Path Latency  (64b): Sum of the latency values throughout the path, in microseconds.

As the packet traverses the switches, they add their Switch_id, Hop Latency,   Ingress and Egress Timestamps, Queue Depth and Wait Time in Queue. The Hop Latency is calculated as Egress Timestamp - Ingress Timestamp.

The metadata is truncated from the packet that returns to S2, and it is only forwarded the TCP Option with the relevant information for the latency-based load balancing, reducing the network overhead.

Apart from the INT P4 and Network Startup Code, this Repository also contains:

* `Telemetry Monitoring System` - provides a Telemetry Server implementation, with the INT Collector Source and InfluxDB Instructions.

* `Wireshark Dissector` - contains a Wireshark parser for the INT Headers defined in this implementation.

* `NTP` - Redefined BMV2 and V1Model Source Codes.

* `Documentation` - relevant documentation regarding this implementation.
 

### Running Instructions

1. In your shell, run:

```bash
make run 
```

   This will:
   * compile `INT.p4`, and
   * start a Mininet instance with all the network nodes

2. Open another shell and run the Controller:


```bash
./mycontroller.py
```

This will establish a gRPC Connection with the switches to perfom the P4 Runtime Service, install the INT.p4 program on them and push all implementarion Rules. The interface between the switch and the control plane is defined in the INT.p4.p4info file. 


### Load Balancing Testing

To test the load balancing algorithm we will be using Iperf 2 as TCP Traffic generator.

After deploying the INT Environment:

1. start an Iperf Server in the background

```bash
h2 iperf -s &
```

2. Run and Iperf Client in H1

```bash
h1 iperf -c h2 -M 1200 -t 600 -P 10
```

**Note**

As specified in section 5.3 of INT specification, the introduction of INT data by the Switches has to be considered for MTU purposes.

The flag "-M" is utilized for limiting the TCP MSS to 1200 Bytes, as the default packets have 1500 Bytes, and the default Mininet network interface’s MTU is 1500 Bytes.

The "-P" flag is utilized to set the number of parallel connections to the server and can be helpful to generate different test cases.

The "-t" flag specifies the test duration.

The link's bandwith can be limited in `Topology.json`. Example for 10 Mbits/s:

```bash
["s4-p2", "s5-p2","0",10]
```




### NTP Notes

The default Timestamps, in microseconds, implemented in BMV2 Switch Target rely on switch startup time. If there is a packet being sent 10 seconds after the program starts up, the ingress timestamp on S1 is 10 seconds. In this particular INT System, this behaviour would lead to a large uncertainty in latency measurement as not all the Switches start at the same time neither have the same startup time. 

To overcome this issue, the BMV2 simple_switch_grpc Source Code was modified to implement Network Time Protocol (NTP) using `gettimeofday` System Function, which outputs the System Type since  the Unix Epoch, 00:00:00 January 1, 1970 Coordinated Universal Time (UTC) . 

This change had to be reflected in V1Model Source Code as well, as this Framework was coded to receive 48 bits Timestamps, but we need 64 to represent the current system time with microseconds precision.

NTP Folder provides the modified the BVM2 and V1Model source codes.

To use this modifications, both BMV2 and P4C (that includes V1Model) have to be recompiled, following the steps provided in their official Github Repository:

1. BMV2

```bash
https://github.com/p4lang/behavioral-model/tree/main#installing-bmv2-from-source

Modified Files: /tagets/simple_switch.cpp && /targets/simple_switch.h
```


2. P4C

```bash
https://github.com/p4lang/p4c#installing-p4c-from-source

Modified File: p4include/v1model.p4
```


#### Cleaning up Mininet

Use the following command to clean up all the files:

```bash
make clean
```

## Relevant Documentation

P4_16, P4 Runtime and INT Specification: https://p4.org/specs/

BMV2 Repository: https://github.com/p4lang/behavioral-model

V1Model Repository: https://github.com/p4lang/p4c/blob/main/p4include/v1model.p4

Some reference Github repositories for this implementation:

    1. https://github.com/cslev/p4tutorial (for the Arp implementation)

    2. https://github.com/GEANT-DataPlaneProgramming/int-platforms

    3. https://github.com/p4lang/p4app-TCP-INT
