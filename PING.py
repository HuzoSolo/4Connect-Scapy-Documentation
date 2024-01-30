# ping taraması ile ağdaki cihazların ip adreslerini bulma

from ping3 import ping, verbose_ping
# ping3 kütüphanesi ping paketi oluşturmak için kullanılıyor
# ping kısmı ping paketi oluşturuyor
# verbose_ping kısmı ping paketini gönderiyor ve yanıtı alıyor

def ping_scan(target_ip, _timeout=2):
    # timeout kısmı yanıt gelmezse ne kadar bekleyeceğini belirtiyor
    # Ping taraması yap
    result = ping(target_ip, timeout=_timeout)
    # ping kısmı ping paketi oluşturuyor
    #result adlı değişkenin tipi float
    # Sonuçları kontrol et
    if result is not None:
        # ping paketi alındı
        print(f"{target_ip} is reachable. Round-trip time: {result} ms")
    else:
        print(f"{target_ip} is unreachable.")

if __name__ == "__main__":
    target_ip = input("Hedef IP adresini girin:")  # Hedef IP adresi

    ping_scan(target_ip)
