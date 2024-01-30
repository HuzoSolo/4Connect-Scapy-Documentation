from scapy.all import *
import logging

logging.getLogger("scapy").setLevel(logging.CRITICAL)

def hello_world(dst_ip_address):
    # ICMP paketi oluştur
    packet = IP(dst=dst_ip_address) / ICMP() / "Hello, World!"
    # burada ICMP() / "Hello, World!" kısmı ICMP paketinin içine bir mesaj eklemek için kullanılıyor
    # dst kısmı hedef ip adresini belirtiyor
    # ICMP() kısmı ICMP paketi oluşturuyor
    # IP() kısmı IP paketi oluşturuyor

    # Paketi gönder
    response = sr1(packet, timeout=2, verbose=10)
    # sr1 fonksiyonu paketi gönderiyor ve yanıtı alıyor
    # timeout kısmı yanıt gelmezse ne kadar bekleyeceğini belirtiyor
    # verbose kısmı paketin gönderilmesi ve yanıtın alınmasıyla ilgili bilgileri ekrana yazdırıyor 

    # Yanıt var mı kontrol et
    if response:
        print("Response received:")
        response.show()
        if(response.haslayer(IP) and response[IP].ttl <= 64):
            print("Response received from a Linux machine.")
        elif(response.haslayer(IP) and response[IP].ttl <= 128):
            print("Response received from a Windows machine.")
        else:
            print("Response received from a Cisco machine.")
        
        if(response.haslayer(ICMP) and response[ICMP].type == 0):
            print("ICMP echo reply received.")
        elif(response.haslayer(ICMP) and response[ICMP].type == 3):
            print("Destination unreachable.")
        elif(response.haslayer(ICMP) and response[ICMP].type == 8):
            print("ICMP echo request received.")
        elif(response.haslayer(ICMP) and response[ICMP].type == 11):
            print("Time exceeded.")
        else:
            print("Unknown ICMP type.")




    else:
        print("No response received.")

if __name__ == "__main__":
    dst_ip_address = input("Hedef IP adresini giriniz: ")  # Hedef IP adresi

    hello_world(dst_ip_address)
