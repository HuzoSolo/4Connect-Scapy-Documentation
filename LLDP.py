from scapy.all import Ether, Dot3, Raw, sendp, getmacbyip

def get_mac_address(ip):
    try:
        mac = getmacbyip(ip)
        return mac
    except Exception as e:
        print(f"Error getting MAC address for IP {ip}: {e}")
        return None

def send_lldp_packet(target_ip, source_ip, source_port):
    source_mac = get_mac_address(source_ip)

    if source_mac:
        # LLDP paketi oluştur
        lldp_packet = Ether(dst="01:80:c2:00:00:0e", src=source_mac, type=0x88cc) / \
                      Dot3() / \
                      LLDPU(ttl=120, endmark=1) / \
                      Raw(load=f"\x02\x07\x04{source_ip}\x06\x02{source_port}\x00")

        # Belirtilen IP adresine LLDP paketini gönder
        sendp(lldp_packet, iface="eth0", verbose=0, dst=target_ip)

# Örnek kullanım
target_ip = "192.168.0.1"  # Hedef IP adresini belirtin
source_ip = "192.168.0.19"  # Kaynak IP adresini belirtin (örneğin, kendi IP adresiniz)
source_port = "Ethernet 4"  # Kaynak port bilgisini belirtin

send_lldp_packet(target_ip, source_ip, source_port)
