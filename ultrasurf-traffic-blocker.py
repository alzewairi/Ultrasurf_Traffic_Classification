#!/usr/bin/env python

from scapy.all import *
from socket import AF_INET
from multiprocessing import Process
from multiprocessing.managers import SyncManager
from datetime import datetime
import sys
import signal
import nfqueue
import traceback
import logging

lanNIC = 'eth0'                                              # LAN facing network card
wanNIC = 'eth1'                                              # Internet facing network card
fileQuarantine = 'u-quarantine.log'                          # File contains quarantined private IPs
domains = {'google': '3', 'appspot': '2', 'amazonaws': '1'}  # DNS Domains and their rank value
ipRank = {}                                                  # Rank value for each private IP
ipQuarantine = []                                            # List of quarantined private IPs
ipDnsDelayed = []                                            # List of private IPs under observation
queues = []                                                  # List of NFQueues
processes = []                                               # List of processes
delayTime = 3                                                # DNS delay period in seconds
EXITCODE = -1                                                # Exit Code
EXCEPTIONS_FILE = '/tmp/u-exception-stack-trace'             # Exception stack trace file


class DnsRrType(object):
    """
    DNS Record Type
    """
    A = 1   # A-record
    NS = 5  # Name Server record


def manager_initialize():
    """
    Function to initialization SyncManager
    :return:
    """
    signal.signal(signal.SIGINT, signal.SIG_IGN)  # tell SyncManager to ignore KeyboardInterrupt signals (SIGINT)


def callback_https(i, payload):
    """
    Function to handle queued HTTPS packets
    :param i:
    :param payload:
    :return:
    """
    try:
        data = payload.get_data()
        pkt = IP(data)
        if pkt[IP].src in ipQuarantine:
            print str("[ ! ]\t%s\t%s\t%s\t%s" % (datetime.fromtimestamp(pkt.time), pkt[IP].src, pkt[IP].dst, pkt[TCP].dport))
            os.system('sudo ip route add blackhole %s' % (pkt[IP].src))
        elif pkt[IP].src in ipDnsDelayed:
            print str("[ - ]\t%s\t%s\t%s\t%s" % (datetime.fromtimestamp(pkt.time), pkt[IP].src, pkt[IP].dst, pkt[TCP].dport))
            payload.set_verdict(nfqueue.NF_DROP)
        else:
            print str("[ + ]\t%s\t%s\t%s\t%s" % (datetime.fromtimestamp(pkt.time), pkt[IP].src, pkt[IP].dst, pkt[TCP].dport))
            payload.set_verdict(nfqueue.NF_ACCEPT)
    except KeyboardInterrupt:
        return
    except:
        pass


def callback_dns(i, payload):
    """
    Function to handle queued DNS packets
    :param i:
    :param payload:
    :return:
    """
    try:
        data = payload.get_data()
        pkt = IP(data)
        if pkt.haslayer(DNSQR):
            tick = False
            for domain in domains:
                if domain in pkt[DNS].qd.qname:
                    if pkt[IP].src not in ipDnsDelayed:
                        ipDnsDelayed.append(pkt[IP].src)
                    thread.start_new_thread(set_rank, (pkt[IP].src, domain, ))
                    tick = True
                    break

            if tick:
                print str("[ * ]\t%s\t%s\t%s\t%s" % (datetime.fromtimestamp(pkt.time), pkt[IP].src, pkt[IP].dst, pkt[DNS].qd.qname[:-1]))
                thread.start_new_thread(delay_dns, (payload, delayTime, ))
            else:
                print str("[ + ]\t%s\t%s\t%s\t%s" % (datetime.fromtimestamp(pkt.time), pkt[IP].src, pkt[IP].dst, pkt[DNS].qd.qname[:-1]))
                payload.set_verdict(nfqueue.NF_ACCEPT)
    except KeyboardInterrupt:
        return
    except:
        pass


def delay_dns(payload, period):
    """
    Function to handle the delay of DNS requests
    :param payload:
    :param period:
    :return:
    """
    try:
        time.sleep(period)  # delay DNS request query
        payload.set_verdict(nfqueue.NF_ACCEPT)  # pass an ACCEPT verdict
        # remove ip from delayed queue
        data = payload.get_data()
        pkt = IP(data)
        ipDnsDelayed.remove(pkt[IP].src)
    except:
        pass


def set_rank(srcIP, domain):
    """
    Function to calculate the rank value of private IP addresses
    :param srcIP:
    :param domain:
    :return:
    """
    try:
        if srcIP in ipRank:
            if not domains[domain] in ipRank.get(srcIP):
                ipRank[srcIP] += domains[domain]
        else:
            ipRank[srcIP] = domains[domain]
        score = 0
        for domain in domains:
            if domains[domain] in ipRank[srcIP]:
                score += 1
            if score == 3:
                add_quarantine(srcIP)
    except:
        pass


def add_quarantine(ip):
    """
    Function to add an IP address to the quarantine list
    :param ip:
    :return:
    """
    try:
        if ip in ipQuarantine:
            return
        ipQuarantine.append(ip)
        ipDnsDelayed.remove(ip)
        del ipRank[ip]
    except:
        pass


def set_iptables():
    """
    Function to initialize the IPTables
    :return:
    """
    try:
        os.system('echo 1 > /proc/sys/net/ipv4/ip_forward')
        os.system('iptables -A FORWARD -i %s -o %s -j ACCEPT' % (wanNIC, lanNIC))
        os.system('iptables -A FORWARD -i %s -o %s -m state --state NEW,ESTABLISHED,RELATED -p udp --dport 53 -j NFQUEUE --queue-num 0' % (lanNIC, wanNIC))
        os.system('iptables -A FORWARD -i %s -o %s -m state --state NEW,ESTABLISHED,RELATED -p tcp --dport 80 -j NFQUEUE --queue-num 1' % (lanNIC, wanNIC))
        os.system('iptables -A FORWARD -i %s -o %s -m state --state NEW,ESTABLISHED,RELATED -p tcp --dport 443 -j NFQUEUE --queue-num 1' % (lanNIC, wanNIC))
        os.system('iptables -A FORWARD -i %s -o %s -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT' % (lanNIC, wanNIC))
        os.system('iptables -t nat -A POSTROUTING -o %s -j MASQUERADE' % wanNIC)
    except:
        pass

def unset_iptables():
    """
    Function to de-initialize the IPTables
    :return:
    """
    try:
        os.system('echo 0 > /proc/sys/net/ipv4/ip_forward')
        os.system('iptables -F; sudo iptables -X')
    except:
        pass


def unset_routing():
    """
    Function to de-initialize the routing tables
    :return:
    """
    try:
        for ip in ipQuarantine:
            os.system('ip route del %s' % ip)
    except:
        pass


def set_quarantine(path):
    """
    Function to initialize quarantine list from a file
    :param path:
    :return:
    """
    try:
        cat = os.popen('cat %s' % path).read()
        (ipQuarantine.append(line) for line in cat.split('\n') if len(line) != 0)
    except:
        pass


def update_quarantine_file(path):
    """
    Function to update quarantine file
    :param path:
    :return:
    """
    try:
        data = ''
        for ip in ipQuarantine:
            data += str("%s\n" % ip)
        os.system('echo "%s" > %s' % (data, path))
    except:
        pass


def create_queue(queue_number, callback_function):
    """
    Function to create and initialize NFQueue
    :param queue_number:
    :param callback_function:
    :return:
    """
    try:
        queue = nfqueue.queue()
        queue.set_callback(callback_function)
        queue.fast_open(queue_number, AF_INET)
        queue.set_queue_maxlen(65535)
        return queue
    except:
        pass

def release_all_queues():
    """
    Function to unbind and close all NFQueues
    :return:
    """
    try:
        for queue in queues:
            if queue is not None:
                queue.unbind(socket.AF_INET)
                queue.close()
    except:
        pass


def run_queue(queue, *args):
    """
    Function to run NFQueue
    :param queue:
    :param args:
    :return:
    """
    try:
        queue.try_run()
    except KeyboardInterrupt:
        return
    except:
        pass


def print_banner():
    """
    Function to print the Banner
    :return:
    """
    print ''
    print 'Ultrasurf 13.04 blocker - Version 2.0'
    print '"And if we burn, you burn with us."'
    print '\n'


def main():
    """
    Main Function
    :return:
    """
    try:
        logging.basicConfig(level=logging.DEBUG, filename=EXCEPTIONS_FILE)
        global ipQuarantine, ipDnsDelayed, ipRank, EXITCODE
        os.system('date')
        print_banner()

        manager = SyncManager()            # Instance of SyncManager to synchronize between multiple processes
        manager.start(manager_initialize)  # Initialize SyncManager

        ipQuarantine = manager.list()      # List of quarantine private IPs running UltraSurf
        ipDnsDelayed = manager.list()	   # List of private IPs currently have DNS packet delayed
        ipRank = manager.dict()		   # Dictionary of private IPs connecting through Firewall

        set_iptables()			   # Setup IPTables
        # set_ipQuarantine(fileQuarantine) # Initialize quarantined IPs list from a log file

        queues.append(create_queue(0, callback_dns))    # Create a NFQueue (queue-0) to handle DNS traffic
        queues.append(create_queue(1, callback_https))  # Create a NFQueue (queue-1) to handle HTTPS traffic

        # Run each NFQueue in its own background process
        for index, queue in enumerate(queues):
            processes.append(Process(target=run_queue, args=(queue, ), name=str('Avox:%d/%d' % (index, len(queues)-1))))
            processes[index].daemon = True
            processes[index].start()
            print '%s was dispatched.' % processes[index].name

        # Keep the program running as long as there is any process running or keyboard interrupt signal is NOT pressed
        while len(processes) > 0:
            (time.sleep(1) if process.is_alive() else processes.pop(process) for process in processes)

        EXITCODE = 0

    except KeyboardInterrupt:
        EXITCODE = 1
    except:
        traceback.print_exc()
        logging.exception(datetime.now())
    finally:
        (process.terminate() for process in processes if process.is_alive())  # Terminate any running process
        release_all_queues()  # De-initialize all NFQueues
        unset_iptables()      # Reset IPTables
        # update_quarantine_file(fileQuarantine)  # Update quarantined IPs file
        unset_routing()       # Reset routing table rules
        os.system('date')
        sys.exit(EXITCODE)


main()
