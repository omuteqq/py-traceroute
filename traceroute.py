import socket
import struct
import time
import argparse
import sys
import os

ICMP_ECHO_REQUEST = 8
ICMP_TIME_EXCEEDED = 11
ICMP_CODE = socket.getprotobyname("icmp")
MAX_HOPS = 30
PACKET_SIZE = 60
TIMEOUT = 5.0

def checksum(source_string):
    sum = 0
    count_to = (len(source_string) // 2) * 2
    for count in range(0, count_to, 2):
        sum += (source_string[count + 1] << 8) + source_string[count]
    if count_to < len(source_string):
        sum += source_string[-1]
    sum = (sum >> 16) + (sum & 0xffff)
    sum += (sum >> 16)
    return ~sum & 0xffff

def create_packet():
    pid = os.getpid() & 0xFFFF
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, 0, pid, 1)
    data = b"Q" * (PACKET_SIZE - len(header))
    chksum = checksum(header + data)
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, chksum, pid, 1)
    return header + data

def resolve_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return ip

def traceroute(target, resolve=False):
    try:
        dest_ip = socket.gethostbyname(target)
    except socket.gaierror:
        print(f"Не удалось разрешить {target}")
        sys.exit(1)
    
    print(f"Трассировка маршрута к {target} [{dest_ip}]\n")
    
    for ttl in range(1, MAX_HOPS + 1):
        with socket.socket(socket.AF_INET, socket.SOCK_RAW, ICMP_CODE) as send_sock, \
             socket.socket(socket.AF_INET, socket.SOCK_RAW, ICMP_CODE) as recv_sock:
            send_sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, struct.pack('I', ttl))
            recv_sock.settimeout(TIMEOUT)
            recv_sock.bind(("", 0))
            
            packet = create_packet()
            send_sock.sendto(packet, (dest_ip, 0))
            start_time = time.time()
            
            try:
                data, addr = recv_sock.recvfrom(512)
                elapsed = (time.time() - start_time) * 1000
                addr_ip = addr[0]
                addr_name = resolve_hostname(addr_ip) if resolve else addr_ip
                print(f"{ttl}\t{elapsed:.2f} ms\t{addr_name} [{addr_ip}]")
                if addr_ip == dest_ip:
                    break
            except socket.timeout:
                print(f"{ttl}\t*\tЗапрос истёк")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Traceroute на Python")
    parser.add_argument("target", help="IP-адрес или доменное имя целевого узла")
    parser.add_argument("-r", "--resolve", action="store_true", help="Разрешение IP-адресов в имена узлов")
    args = parser.parse_args()
    traceroute(args.target, args.resolve)
