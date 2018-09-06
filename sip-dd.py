import os
import time
import argparse
import calendar
import datetime
import threading
import pickle
from datetime import timedelta
from collections import defaultdict, Counter
from scapy.all import *

MAX_UDP_SIP_PACKET_SIZE = 64 # kb
RATE_CALCULATE_INTERVAL = 1 # sec - smaller is more accurate but slower

def _get_dump_file_names():
    """Calculate the filenames that the PCAP data to be written from the now(DateTime)
    hourly/13:00-14:00_28.Nov.2017.pcap
    daily/28.Nov.2017.pcap
    weekly/21-28_Nov.2017
    monthly/Nov.2017
    """
    now = datetime.now()

    abbr_month_name = calendar.month_name[now.month][:3]
    start_day_of_week = (now - timedelta(days=now.weekday())).day
    end_day_of_week = (now - timedelta(days=now.weekday()) + \
        timedelta(days=7)).day

    hfn = 'hourly/%d:00-%d:00_%d.%s.%d' % (now.hour, now.hour+1, now.day, 
        abbr_month_name, now.year)
    dfn = 'daily/%d.%s.%d' % (now.day, abbr_month_name, now.year)
    wfn = 'weekly/%d-%d_%s.%d' % (start_day_of_week, end_day_of_week, abbr_month_name, 
        now.year)
    mfn = 'monthly/%s.%d' % (abbr_month_name, now.year)

    return [('hourly', hfn), ('daily', dfn), ('weekly', wfn), ('monthly', mfn)]

# TODO: Write a mock way to simulate traffic from a pcap file(for testing)

class SipDDSniffer(object):
    """ 
    XXX

    Note: I don't care too much about thread-safety since data intensive stuff happens
    on files, only simple conf./status is passed between threads.
    """

    def __init__(self, args):
        self.args = args
        self.in_packet_rate_limit=self.args.inbound_traffic_rate_in_kbps/MAX_UDP_SIP_PACKET_SIZE
        
        self.total_len_in_bytes = 0
        self.current_rate_in_kpbs = 0 # kbps
        self.counters = {}
        self.rates = {}

    def _load_rates(self):
        for period, file_name in _get_dump_file_names():
            try:
                with open(file_name + '.rates', 'rb') as f:
                    self.rates[period] = pickle.load(f)
            except FileNotFoundError:
                self.rates[period] = {'total_sum':0, 'sample_count': 0, 'max': 0}

    def current_edge(self, period):
        return self.current_rate_in_kpbs

    def normal_edge(self, period):
        return self.rates[period]['total_sum'] / self.rates[period]['sample_count']

    def attack_edge(self, period):
        return self.rates[period]['max']

    def suspect_edge(self, period):
        return (self.attack_edge(period) + self.normal_edge(period)) / 2

    def current_limit(self, period):
        return (self.current_edge(period) / MAX_UDP_SIP_PACKET_SIZE)

    def normal_limit(self, period):
        return (self.normal_edge(period) / MAX_UDP_SIP_PACKET_SIZE)
    
    def suspect_limit(self, period):
        return (self.suspect_edge(period) / MAX_UDP_SIP_PACKET_SIZE)
    
    def attack_limit(self, period):
        return (self.attack_edge(period) / MAX_UDP_SIP_PACKET_SIZE)
    
    def _calc_rate(self):
        PACKET_DROP_INTERVAL = 5*60 # secs
        prev_tot_len = self.total_len_in_bytes
        while(True):
            self.current_rate_in_kpbs = \
                (self.total_len_in_bytes-prev_tot_len) / 1024 / RATE_CALCULATE_INTERVAL
            prev_tot_len = self.total_len_in_bytes
            
            # save rates
            for period, file_name in _get_dump_file_names():
                self.rates[period]['total_sum'] += self.current_rate_in_kpbs
                self.rates[period]['sample_count'] += 1
                self.rates[period]['max'] = max(self.rates[period]['max'], self.current_rate_in_kpbs)
                with open(file_name + '.rates', 'wb') as f:
                    pickle.dump(self.rates[period], f)

                if self.current_edge(period) > self.suspect_edge(period) or \
                    self.current_limit(period) > self.suspect_limit(period):

                    # traverse all counters and check if any of them exceeds the suspect limit
                    for rule_no, counter in self.counters['rules'].items():
                        for ip, v in counter.items():
                            if v > self.suspect_limit(period):
                                print('Rule %d is activated. There may be an attack'
                                    ' from %s.' % (rule_no, ip))
                                # TODO: Send email
                            if v > self.attack_limit(period):
                                print('There was an attack from %s. SIP packets are being'
                                    ' blocked for %d mins.' % (ip, PACKET_DROP_INTERVAL//60))
                                # TODO: Send email
                                # TODO: Drop packets
                            # current SIP traffic is more than %95 of SIP packet rate limit
                            if v >= ((95*self.in_packet_rate_limit) // 100):
                                print('There was an attack from %s.(in_packet_rate saturated.) SIP packets are being'
                                    ' blocked for %d mins.' % (ip, PACKET_DROP_INTERVAL//60))
                                # TODO: Send email
                                # TODO: Drop packets

            # counters hold the rule related data
            self.counters = {'rules': {1: Counter(), 2: Counter(),}}

            time.sleep(RATE_CALCULATE_INTERVAL)

    def _on_pkt_recv(self, pkt):
        try:
            print("packet received...")
            for _, file_name in _get_dump_file_names():
                wrpcap(file_name + '.pcap', pkt, append=True)
            
            self.total_len_in_bytes += pkt.len

            try:
                # TODO: For lab purpose we will use the IP address in From header in the Application Layer.
                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst
                sip_data = pkt[Raw].load.decode('utf-8')

                # TODO: I am sure there is a better alternative to extract CSeq 
                # value from a sip msg but this simply works.
                cseq = None
                sip_data_splitted = sip_data.split()
                for i, a in enumerate(sip_data_splitted):
                    if a == b'CSeq:':
                        cseq = sip_data_splitted[i+1]
                        break
                if cseq is None:
                    raise Exception("CSeq not found.")
            except IndexError:
                return

            # Rule-1
            if any(x in sip_data for x in ['INVITE sip', 'REGISTER sip']):
                self.counters['rules'][1][src_ip] += 1

            # Rule-2
            if any(x in sip_data for x in ['INVITE sip', 'REGISTER sip']):
                self.counters['rules'][2][dst_ip] += 1

        except Exception as e:
            import traceback; traceback.print_exc()

    def _sniff(self):
        sniff(iface=self.args.dev_name, prn=self._on_pkt_recv, 
            filter=self.args.bpf_filter, store=0)

    def start(self):
        self._load_rates()

        self._rate_calculator_thread = threading.Thread(target=self._calc_rate, args=())
        self._rate_calculator_thread.start()

        self._sniffer_thread = threading.Thread(target=self._sniff, args=())
        self._sniffer_thread.start()

def main():
    parser = argparse.ArgumentParser(description='SIP DoS Defense Tool')
    parser.add_argument('--dev_name', '-d', type=str, required=True)
    parser.add_argument('--verbose', '-v', action='store_true')
    parser.add_argument('--bpf_filter', '-f', type=str, default='udp port 5060')
    parser.add_argument('--inbound_traffic_rate_in_kbps', '-t', type=int, required=True)

    args = parser.parse_args()

    # ensure save output dirs are in place
    for d in ['daily', 'hourly', 'weekly', 'monthly']:
        if not os.path.exists(d):
            os.makedirs(d)

    # start our sniffer
    sniffer = SipDDSniffer(args)
    sniffer.start()

if __name__ == "__main__":
    main()

"""
a=rdpcap(_get_dump_file_names()[3]+'.pcap')
for p in a:
    if IP in p: # can be IPv6 
        print(p[IP].src)
        print(p[UDP])
        #if Raw in p:
        print(p[Raw].load)
    #p.show()    
    #print(dir(p))
    #print(p[IP].src)
    #print(p[UDP])
"""
