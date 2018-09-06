SIP-Based DDoS Defense Tool

* Architecture : Melih Tas
* Code: Sumer Cip

SIP-DD is a defense tool developed against SIP-based DoS/DDoS attacks. In the current state, SIP-DD comprises 3 main modules namely with Statistics, Inspection and Action.

Originally it was developed to be used in academic work to help developing novel defense approaches and then as an idea to convert it to a fully functional application level SIP-based DDoS mitigation tool.

It has been used in an academic journal paper titled "Novel SIP-based DDoS Attacks and Effective Defense Strategies" published in Computers & Security 63 (2016) 29-44 by Elsevier, Science Direct http://sciencedirect.com/science/article/pii/S0167404816300980.

SIP-DD uses pcap library which keeps a queue at the kernel level and allows to examine the asynchronous data, and it does detection after the actual traffic copy is received. Calculation method takes interval approximately 4-5 seconds considering the performance. SIP-DD also does multi-threading rate control.

Statistics Module collects a window of traffic periodically (hourly, daily, weekly, monthly) and for each of them, it creates a sample traffic pattern especially considering network and SIP packet specifications. This sample is named normal traffic pattern. The sampled network traffic is used as the input for the learning and calculation mechanism to obtain statistics for generating the dynamic thresholds employed by the action module in the defense mechanism. According to threshold calculation, there should be initial inbound and outbound traffic values defined. Measuring the bandwidth usages and packets per seconds for a time period, the learning mechanism calculates the attack traffic threshold.

When the current traffic rate reaches the attack traffic threshold, the Inspection Module becomes active and compares the normal traffic pattern to the suspected attack traffic pattern. Inspecting the SIP specifications that include the headers and tags in SIP messages such as Call-ID, from tag, branch tag, etc. running the following attack-specific detection rules, the mechanism aims to identify how much of the suspicious traffic is auto-generated and should be dropped/blocked in Action module of the defense mechanism.

* Rule 1: Incoming SIP connections/requests per second from a single source IP address. 
* Rule 2: Incoming SIP connections/requests per second to a single destination IP address. 
* Rule 3: Incoming SIP connections, including retransmission, from a single source IP address. 
* Rule 4: Incoming SIP connections, including retransmission, to a single destination IP address.

Current features: 

* Multi-threading rate control 
* Write live traffic to Pcap files (hourly, weekly, monthly, daily) (appending is supported) 
* If app closed/opened, writing PCAP files and sniffing resumes from where it was (all edge/limit counters make their calculations with respect to these absences) 
* Calculate all limit/edge values defined in the spec. 
* Calculate rule counters defined in the spec.

Future feaures: 

* If there is an attack, SIP-DD will catch the IP address, print it to the console, send email alarms, active blocking mechanism and check if it is an retransmission attack.
* Attack scenario based rules

Usage:

install requirements.txt python3 sip_dd.py -d <device_name> -t <inbound_traffic_limit_in_kbps> -v (VERBOSE logging on) -f <bpf_filter>

If no bpf filter given, default is 'udp port 5060'
