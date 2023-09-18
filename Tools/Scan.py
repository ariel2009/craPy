# import required network modules
import ipaddress
from ServeClasses import Networking
from scapy.all import *
from scapy.layers.l2 import ARP, Ether
from ipaddress import IPv4Network
from concurrent.futures import ThreadPoolExecutor
import socket


# Constructor
class Scan:
    def __init__(self, net="127.0.0.1", port=0):
        self.ans = None
        self.net = net
        self.port = port
        self.ip_to_scan = "127.0.0.1"

    # Function for arp scan by givven ip/s
    def arp_scan(self, ip_to_scan="127.0.0.1", is_for_arp=True):
        '''
        Function for scanning alive hosts by arp protocol
        :param ip_to_scan:
        :param is_for_arp: say if the scan is part of port scan or not
        :return: Arp scan only - Verbose details aboute alive hosts
                 As prepare for port scan - Minimal information required for efficient port scanning
        '''
        if is_for_arp:
            # If for arp scan only by hitting "main.py scan -sA [ip/s,host/s]"
            ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff") /
                             ARP(pdst=ip_to_scan), timeout=1, verbose=1)  # Create an arp packet with the given ip/s
            ans.summary(lambda s, r: r.sprintf("%Ether.src% %ARP.psrc%"))  # Send and recv the packet with details
        else:
            # If for arp scan as prepare to multihost port scan "main.py scan -p [port/s] -h [hosts]"
            ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff") /
                             ARP(pdst=ip_to_scan),
                             timeout=1, verbose=0)  # The same like the previous "if" but set verbose to "0"
            if ans:
                # If response succeed, return its details to the port scanner
                _, response = ans[0]
                return response[ARP].psrc

    def port_scan(self):
        '''
        Function for port scanning against alive hosts only(given from arp_scan)
        :print: details of each host with its open port/s
        '''
        port_arr = self.port_calc()
        try:
            ip_from_str = IPv4Network(self.net)  # Convert ip as text to ip address object
        except ipaddress.AddressValueError:  # If given text is domain, convert it to ip
            ip_str = socket.gethostbyname(self.net)
            ip_from_str = [ip_str]
        for one_ip in ip_from_str:
            '''
            Check host by host if it's alive
            '''
            is_to_scan = one_ip
            self.ip_to_scan = is_to_scan
            if self.is_ip_in_lan():  # If host in the same lan network so be sure if is alive
                is_to_scan = self.arp_scan(str(one_ip), False)
                if not is_to_scan:
                    continue
            self.ip_to_scan = is_to_scan
            with ThreadPoolExecutor(25) as executor:
                # Multithreading port scanning host by host
                results = executor.map(self.scan_one_port, port_arr)
                for port_num, is_open in zip(port_arr, results):
                    if is_open is not None:
                        print(is_open)  # prints port scan result

    def port_calc(self):
        '''
        Function implements Algorithm for generating
        valid port range by given format [0-999,1000,1001-1099]
        :return: Array of all ports including in the given format
        '''
        port_str = str(self.port)
        comma_arr = port_str.split(',')  # First, split text by ","
        finished_arr = []
        for search_dash in comma_arr:
            if '-' in search_dash:  # If there are "-" chars after split by ",", split again by "-"
                dash_range = search_dash.split('-')
                for dash_one_port in range(
                        int(dash_range[0]),
                        int(dash_range[1])):  # append all ports are in the range between each "-"
                    finished_arr.append(dash_one_port)
            else:
                finished_arr.append(int(search_dash))
        return finished_arr

    def scan_one_port(self, port_to_scan):
        '''
        Function for scan one port as called from port_scan and return it
        to port_scan to complete the full scan
        :param port_to_scan: got from port_scan
        :return: open ports on remote host
        '''

        '''
        Try to connect with socket to the remote host
        '''
        scan_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        scan_socket.settimeout(1)
        result = scan_socket.connect_ex((str(self.ip_to_scan), int(port_to_scan)))
        if result == 0:  # If port is open, return it
            state_msg = "Port {0} is open in {1}".format(port_to_scan, str(self.ip_to_scan))
            scan_socket.close()
            return state_msg

    def print_arp_scan(self):
        '''
        Called directly from the Instruction class if user selected arp scan only
        :return: details of the alive hosts
        '''
        self.arp_scan(self.net)
        return False

    def is_ip_in_lan(self):
        # Check if poovided ip is in the current lan network
        network_obj = Networking.Networking()
        scaned_net = network_obj.comp_network_addr(
            self.ip_to_scan)  # compare my ip with remote ip if are in the same network
        return scaned_net
