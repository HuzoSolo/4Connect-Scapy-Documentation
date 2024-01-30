import socket
from scapy.all import *

def get_service_version(target_ip, target_port_start, target_port_end):
    
    for target_port in range(int(target_port_start), int(target_port_end)):
        # TCP paketi oluştur
        packet = IP(dst=target_ip) / TCP(dport=target_port, flags="S")
        # TCP paketi oluşturuyoruz
        # dport kısmı hedef portu belirtiyor
        # flags kısmı TCP paketinin bayraklarını belirtiyor
        # IP() kısmı IP paketi oluşturuyor

        # Paketi gönder
        response = sr1(packet, timeout=2, verbose=0)

        # TCP paketi alındı mı kontrol et
        if response and response.haslayer(TCP) and response[TCP].flags & 0x2:
            # 0x2 = SYN/ACK bayrağı
            # response.haslayer(TCP) kısmı TCP paketi alınıp alınmadığını kontrol ediyor
            # response[TCP].flags & 0x2 kısmı TCP paketinin bayraklarını kontrol ediyor

            
            
            # TCP üçlü el sıkışma (SYN/ACK) yanıtı alındı
            print(f"Port {target_port} is open.")

            # Servis versiyonunu almak için socket kullan
            try:
                service_version = socket.getservbyport(target_port)
                # getservbyport kısmı hedef portun servis versiyonunu alıyor
                # target_port kısmı hedef portu belirtiyor
                print(f"Service version on port {target_port}: {service_version}")
            except socket.error:
                print(f"Service version on port {target_port} is unknown.")
        else:
            print(f"Port {target_port} is closed.")
    
    

if __name__ == "__main__":
    target_ip = input("Hedef IP adresini giriniz: ")  # Hedef IP adresi
    target_port_start = input("starting port for scan") # Hedef port (HTTP servisi için örnek)
    target_port_end = input("ending port for scan")
    get_service_version(target_ip, target_port_start, target_port_end)
