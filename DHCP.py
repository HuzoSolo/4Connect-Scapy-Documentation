from scapy.all import *

def send_dhcp_discover():
    # DHCP Discover paketi oluştur
    dhcp_discover = Ether(src=RandMAC(), dst="ff:ff:ff:ff:ff:ff") / \
                    IP(src="0.0.0.0", dst="255.255.255.255") / \
                    UDP(sport=68, dport=67) / \
                    BOOTP(chaddr=RandString(12), xid=RandInt()) / \
                    DHCP(options=[("message-type", "discover"), "end"])

    # DHCP Discover paketini gönder
    sendp(dhcp_discover, verbose=0)

def sniff_dhcp_responses():
    # Ağdaki DHCP yanıtlarını dinle
    dhcp_responses = sniff(filter="udp and (port 67 or port 68)", count=5)

    # Dinlenen DHCP yanıtlarını ekrana yazdır
    for response in dhcp_responses:
        if DHCP in response:
            print(f"DHCP Response Details:")
            print(f"Transaction ID: {response[BOOTP].xid}")
            print(f"Source MAC: {response[Ether].src}")
            print(f"Client IP: {response[IP].src}")
            print(f"Your IP: {response[IP].dst}")
            print(f"Message Type: {response[DHCP].options[0][1]}")
            print(f"Options: {response[DHCP].options}")
            print("-" * 50)

if __name__ == "__main__":
    # DHCP Discover paketi gönder
    send_dhcp_discover()

    # Ağdaki DHCP yanıtlarını dinle
    sniff_dhcp_responses()
