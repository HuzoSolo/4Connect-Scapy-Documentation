from scapy.all import Ether, Dot3, LLDP, Raw

def send_lldp_packet(target_ip, source_ip, source_port):
    # Ethernet çerçevesini oluştur
    eth_frame = Ether(dst="01:80:c2:00:00:0e", src="00:11:22:33:44:55")

    # Dot3 katmanını ekleyerek Ethernet çerçevesini oluştur
    dot3_frame = Dot3()

    # LLDP katmanını oluştur
    lldp_frame = LLDP(ttl=120)

    # LLDP çerçevesine özel veri yükü (payload) ekleyerek Raw katmanını oluştur
    lldp_payload = Raw(load=f"\x02\x07\x04{source_ip}\x06\x02{source_port}\x00")

    # Çerçeveleri birleştirerek LLDP çerçevesini oluştur
    lldp_packet = eth_frame / dot3_frame / lldp_frame / lldp_payload

    # Belirtilen IP adresine LLDP paketini gönder
    lldp_packet.show()  # Paketi görmek için
    # sendp(lldp_packet, iface="eth0", verbose=0, dst=target_ip)

# Örnek kullanım
target_ip = "192.168.1.1"
source_ip = "192.168.1.2"
source_port = "Ethernet1"

send_lldp_packet(target_ip, source_ip, source_port)
