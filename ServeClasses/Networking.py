import socket
import ipcalc
import netifaces as netifaces


class Networking(BaseException):
    '''
    Assistance class for networking services
    '''

    def __init__(self):

        self.interface = 'eth0'
        self.hostname = socket.gethostname()
        self.my_ip = socket.gethostbyname(self.hostname)

    def get_default_interface(self):
        '''
        Function for get the default network interface
        :return: default interface if there is internet connection
        '''
        gateways = netifaces.gateways()
        try:
            for gateway in gateways[netifaces.AF_INET]:
                if gateway[1] == '0.0.0.0':
                    self.interface = gateway[0]
        except KeyError:
            print("No internet connection.")
            quit()

    def get_network_mask(self):
        '''
        Function for getting subnet mask from ip and interface
        :return:
        '''
        self.get_default_interface()
        if self.interface in netifaces.interfaces():
            addresses = netifaces.ifaddresses(self.interface)
            if netifaces.AF_INET in addresses:
                ipv4_info = addresses[netifaces.AF_INET][0]
                return ipv4_info['netmask']
        return False

    def comp_network_addr(self, ip_to_calc):
        '''
        Function checks if specific ip is in current network
        :param ip_to_calc:
        :return: is provided ip is in current network
        '''
        subnet_mask = self.get_network_mask()
        remote_addr = ipcalc.IP(str(ip_to_calc), mask=subnet_mask)
        my_addr = ipcalc.IP(str(self.my_ip), mask=subnet_mask)
        remote_net = str(remote_addr.guess_network())
        my_net = str(my_addr.guess_network())
        if my_net == remote_net:
            # If the remote network address is the same as my network address
            return True
        return False
