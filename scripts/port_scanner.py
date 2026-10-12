#!/usr/bin/env python3
"""
port_scanner.py — Escáner de puertos TCP básico.

Proyecto de laboratorio para entender, a bajo nivel, qué hace una
herramienta como nmap cuando comprueba qué puertos están abiertos
en un host: abre un socket TCP contra cada puerto y mide si la
conexión se completa (handshake), falla, o no responde (filtrado).

USO:
    python port_scanner.py <host> [--ports 1-1024] [--timeout 0.5] [--threads 100]

EJEMPLOS:
    python port_scanner.py 192.168.1.10
    python port_scanner.py scanme.nmap.org --ports 20-100

⚠️ USO ÉTICO: solo escanea hosts que sean tuyos o para los que tengas
autorización explícita (tu propia máquina, tu home lab, o un objetivo
legal como scanme.nmap.org, pensado precisamente para pruebas).
Escanear sistemas de terceros sin permiso puede ser ilegal.
"""

import argparse
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

# Puertos comunes para dar contexto legible al resultado (no exhaustivo)
COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
    445: "SMB", 3306: "MySQL", 3389: "RDP", 8080: "HTTP-alt",
}


def parse_port_range(port_range: str) -> range:
    """Convierte '1-1024' o '80' en un objeto range."""
    if "-" in port_range:
        start, end = port_range.split("-", 1)
        return range(int(start), int(end) + 1)
    port = int(port_range)
    return range(port, port + 1)


def scan_port(host: str, port: int, timeout: float) -> bool:
    """Intenta completar un TCP connect() al puerto. True si está abierto."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        return result == 0


def main() -> None:
    parser = argparse.ArgumentParser(description="Escáner de puertos TCP básico (uso educativo/autorizado).")
    parser.add_argument("host", help="Host o IP objetivo")
    parser.add_argument("--ports", default="1-1024", help="Rango de puertos, ej. 1-1024 o 80 (default: 1-1024)")
    parser.add_argument("--timeout", type=float, default=0.5, help="Timeout por puerto en segundos (default: 0.5)")
    parser.add_argument("--threads", type=int, default=100, help="Hilos concurrentes (default: 100)")
    args = parser.parse_args()

    try:
        target_ip = socket.gethostbyname(args.host)
    except socket.gaierror:
        print(f"[!] No se pudo resolver el host: {args.host}")
        return

    ports = parse_port_range(args.ports)
    print(f"[*] Escaneando {args.host} ({target_ip}) — puertos {args.ports}")

    open_ports = []
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {executor.submit(scan_port, target_ip, port, args.timeout): port for port in ports}
        for future in as_completed(futures):
            port = futures[future]
            try:
                if future.result():
                    open_ports.append(port)
            except Exception:
                # Puerto no alcanzable / error de red — se ignora como "cerrado/filtrado"
                pass

    print(f"\n[*] Escaneo completado. {len(open_ports)} puerto(s) abierto(s):\n")
    for port in sorted(open_ports):
        service = COMMON_PORTS.get(port, "desconocido")
        print(f"  {port}/tcp\topen\t{service}")

    if not open_ports:
        print("  (ninguno detectado en el rango escaneado)")


if __name__ == "__main__":
    main()
