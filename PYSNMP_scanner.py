from pysnmp.hlapi import *

def get_snmp_info(target_ip, community='public', oid='.1.3.6.1.2.1.1.1.0'):
    error_indication, error_status, error_index, var_binds = next(
        getCmd(SnmpEngine(),
               CommunityData(community),
               UdpTransportTarget((target_ip, 161)),
               ContextData(),
               ObjectType(ObjectIdentity(oid)))
    )

    if error_indication:
        print(f"Error: {error_indication}")
    elif error_status:
        print(f"Error: {error_status} at {error_index}")
    else:
        for varBind in var_binds:
            print(f"{varBind[0]} = {varBind[1].prettyPrint()}")

if __name__ == "__main__":
    target_ip = "192.168.1.1"  # Hedef IP adresi
    community_string = "public"  # SNMP topluluğu (varsayılan olarak genellikle "public" kullanılır)

    get_snmp_info(target_ip, community_string)
