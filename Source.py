import psutil

def get_network_interfaces():
    interfaces = psutil.net_if_addrs()
    return interfaces

# Örnek kullanım
network_interfaces = get_network_interfaces()
print(network_interfaces)
