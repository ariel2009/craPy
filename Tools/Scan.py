import ipaddress

from ServeClasses import Networking
from scapy.all import *
from scapy.layers.l2 import ARP, Ether
from ipaddress import IPv4Network
from concurrent.futures import ThreadPoolExecutor
import socket


class Scan:
    def __init__(self, net="127.0.0.1", port=0):
        self.ans = None
        self.net = net
        self.port = port
        self.ip_to_scan = "127.0.0.1"
        # self.protcl = protcl
        # self.checkprotcl(self.protcl)

    def checkprotcl(self, protcl):
        pass

    def arp_scan(self, ip_to_scan="127.0.0.1", is_for_arp=True):
        if is_for_arp:
            ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_to_scan), timeout=1, verbose=1)
            ans.summary(lambda s,r: r.sprintf("%Ether.src% %ARP.psrc%") )
        # Should be additional features like threading and realtime scan
        else:
            ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_to_scan), timeout=1, verbose=0)
            if ans:
                _, response = ans[0]
                return response[ARP].psrc

    def port_scan(self):
        port_arr = self.port_calc()
        try:
            ip_from_str = IPv4Network(self.net)
        except ipaddress.AddressValueError:
            ip_str = socket.gethostbyname(self.net)
            ip_from_str = [ip_str]
        for one_ip in ip_from_str:
            is_to_scan = one_ip
            self.ip_to_scan = is_to_scan
            if self.is_ip_in_lan():
                is_to_scan = self.arp_scan(str(one_ip), False)
                if not is_to_scan:
                    continue
            self.ip_to_scan = is_to_scan
            with ThreadPoolExecutor(25) as executor:
                # dispatch all tasks
                results = executor.map(self.scan_one_port, port_arr)
                for port_num, is_open in zip(port_arr, results):
                    if is_open is not None:
                        print(is_open)

    def port_calc(self):
        port_str = str(self.port)
        comma_arr = port_str.split(',')
        finished_arr = []
        for search_dash in comma_arr:
            if '-' in search_dash:
                dash_range = search_dash.split('-')
                for dash_one_port in range(int(dash_range[0]), int(dash_range[1])):
                    finished_arr.append(dash_one_port)
            else:
                finished_arr.append(int(search_dash))
        return finished_arr

    def scan_one_port(self, port_to_scan):
        state_msg = ""
        scan_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        scan_socket.settimeout(1)
        result = scan_socket.connect_ex((str(self.ip_to_scan), int(port_to_scan)))
        if result == 0:
            state_msg = "Port {0} is open in {1}".format(port_to_scan, str(self.ip_to_scan))
            scan_socket.close()
            return state_msg

    def print_arp_scan(self):
        self.arp_scan(self.net)
        return False

    def is_ip_in_lan(self):
        network_obj = Networking.Networking()
        scaned_net = network_obj.comp_network_addr(self.ip_to_scan)
        return scaned_net