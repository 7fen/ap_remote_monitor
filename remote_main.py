#!/usr/bin/env python3

import sys
import os
import subprocess
import re

from signal import SIGINT, signal
from scapy.all import *

def check_iwconfig():
    mon_ifaces = []
    other_ifaces = []
    try:
        proc = subprocess.Popen(['iwconfig'], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    except:
        print('check_iwconfig is failed')
        sys.exit(1)

    output = proc.communicate()[0]
    for line in output.decode().split('\n'):
        if len(line) == 0: continue
        if line[0] != ' ' and 'IEEE 802.11' in line:
            iface = line[:line.find(' ')]
            if iface == 'wlp3s0': continue
            if 'Mode:Monitor' in line:
                mon_ifaces.append(iface)
            else:
                other_ifaces.append(iface)

    return mon_ifaces, other_ifaces

def try_set_mon_mode(iface):
    try:
        os.system('ip link set %s down' % iface)
        proc = subprocess.Popen(['iwconfig', iface, 'mode', 'monitor'],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        os.system('ip link set %s up' % iface)
        if proc.communicate()[1].decode() != '':
            return False
        else:
            return True
    except:
        print('set mon mode is failed')
        sys.exit(1)


def select_one_iface(ifaces):
    if len(ifaces) < 1:
        return ''

    for iface in ifaces:
        if(try_set_mon_mode(iface)):
            return iface

    return ''

def get_monitor_iface():
    mon_ifaces, other_ifaces = check_iwconfig()
    if len(mon_ifaces) > 0:
        return mon_ifaces[0]
    else:
        return select_one_iface(other_ifaces)

def get_supported_channels(mon_iface):
    try:
        for phy in os.listdir('/sys/class/ieee80211'):
            iface_name_path = '/sys/class/ieee80211/' + phy + '/device/net'
            iface_name = os.listdir(iface_name_path)
            if ''.join(iface_name) == mon_iface:
    #            print('find the phy {} for the mon iface {}'.format(phy, mon_iface))
                break
        else:
            print('not find any phy for the mon_iface:', mon_iface)
            sys.exit(1)
    except:
        print('failed to find the phy')
        sys.exit(1)

    try:
        proc = subprocess.Popen(['iw', phy, 'info'], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        output = proc.communicate()[0].decode().split('\n')
    except:
        print('failed to get phy info')
        sys.exit(1)

    channel_lists = []
    for line in output:
        if len(line) == 0: continue
        m = re.search('\*.*MHz \[(.*)\]', line)
        if m and 'disabled' not in line:
            channel_lists.append(int(m.group(1)))

    return sorted(channel_lists), phy

def freq_to_channel(freq):
    if freq == 2484:
        return 14
    elif freq < 2484:
        return (freq - 2407) // 5
    elif freq <= 45000:
        return (freq - 5000) // 5

def get_bandwidth_capability(phy):
    d = {}
    try:
        proc = subprocess.Popen(['iw', phy, 'channels'], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        output = proc.communicate()[0].decode().split('*')
    except:
        print('failed to get phy channels info')
        sys.exit(1)
    for line in output:
        m = re.search(' (.*) MHz[\s\S]*Channel widths: (.*)', line)
        if m:
            d[freq_to_channel(int(m.group(1)))] = m.group(2)
    
    return d

def set_mon_channel(channel):
    bws = channel_bandwidth[channel]
    if 'VHT80' in bws:
        bw = '80MHz'
    elif 'HT40+' in bws:
        bw = 'HT40+'
    elif 'HT40-' in bws:
        bw = 'HT40-'
    else:
        bw = 'HT20'
    
    if channel == 165:
        bw = 'HT20'

    command = 'iw dev ' + mon_iface + ' set channel ' + str(channel) + ' ' + bw
    os.system(command)

def packet_handler(pkt):

    writer = PcapWriter(store_file_path, append = True)
    writer.write(pkt)
    writer.close()

def stop(signal, frame):
    global stop_flag
    print('CTRL + C pressed, exiting...')
    stop_flag = True

def get_stop_flag(pkt):
    return stop_flag

store_file_path = '/tmp/packet_capture.pcapng'
supported_channels = []
channel_bandwidth = {}
mon_iface = ''
stop_flag = False


if __name__ == '__main__':
    signal(SIGINT, stop)
    try:
        action = sys.argv[1]
    except IndexError:
        print('need the action parameter')
        sys.exit(1)
    
    mon_iface = get_monitor_iface()
    if not mon_iface:
        print('not find mon iface')
        sys.exit(1)

    supported_channels, phy = get_supported_channels(mon_iface)
    channel_bandwidth = get_bandwidth_capability(phy)
    #for freq, band in channel_bandwidth.items():
    #    print('freq:{} band:{}'.format(freq, band)) 

    if action == 'get_supported_channels':
        for channel in supported_channels:
            print(channel, end=' ')
    elif action == 'set_mon_channel':
        try:
            channel = sys.argv[2]
        except IndexError:
            print('need to specify the mon channel')
            sys.exit(1)
        
        if int(channel) not in supported_channels:
            print('the mon channel is incorrect')
            sys.exit(1)

        print('set channel')
        set_mon_channel(int(channel)) 
    elif action == 'start_scan':
        os.system('rm -f ' + store_file_path)
        sniff(iface=mon_iface, prn=packet_handler, store=False, stop_filter=get_stop_flag)


