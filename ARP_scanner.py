# ARP tablosu oluşturmak için kullanılan program
from scapy.all import ARP, Ether, srp
import scapy.all as scapy
# burada eklenen Ether kısmı Ethernet paketi oluşturmak için kullanılıyor
# ARP kütüphanesi ARP paketi oluşturmak için kullanılıyor
# srp kısmı paketi gönderiyor ve yanıtı alıyor

def scan_devices(ip_range):
    # ARP isteği oluştur
    arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_range) # dst kısmı hedef MAC adresini belirtiyor burada broadcast adresi kullanılıyor
    # broadcast adresi herkese gönderilir
    # pdst kısmı hedef IP adresini belirtiyor
    # pdst nin anlamı packet destination
    # buradaki syntax Ether() / ARP() şeklinde olmalı
    # sebebi ise paketin içindeki Ethernet paketinin ARP paketinin içinde olması
    # burada bulunan / sembolü paketlerin iç içe olmasını sağlıyor
    # Ether() kısmı Ethernet paketi oluşturuyor
    # ARP() kısmı ARP paketi oluşturuyor

    # Paketi gönder ve yanıtları al
    response, _ = srp(arp_request, timeout=2, verbose=0)# srp kısmı paketi gönderiyor ve yanıtı alıyor
    # timeout kısmı yanıt gelmezse ne kadar bekleyeceğini belirtiyor
    # verbose kısmı paketin gönderilmesi ve yanıtın alınmasıyla ilgili bilgileri ekrana yazdırıyor
    # response, _ şeklinde olmasının sebebi srp fonksiyonunun iki değer döndürmesi
    # response kısmı yanıtı döndürüyor
    # _ kısmı paketi döndürüyor

    # Yanıtları işle
    devices = []
    for sent, received in response:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})
        # psrc kısmı yanıtın içindeki kaynak IP adresini belirtiyor
        # hwsrc kısmı yanıtın içindeki kaynak MAC adresini belirtiyor

    return devices

if __name__ == "__main__":
    target_ip_range = input("Hedef IP aralığını giriniz: ")  # Hedef IP aralığı

    devices = scan_devices(target_ip_range)
    


    print("Devices on the network:")
    print(devices)
    print("---------------------------")
    for device in devices:
        print(f"IP: {device['ip']}, MAC: {device['mac']}")

    arp_result = scapy.arping(target_ip_range)
    print("---------------------------")
    print(arp_result)
    print("---------------------------")
