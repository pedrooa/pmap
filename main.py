import sys
import socket
from scapy.all import *

mode = int(input(
    "Digite 1 para escanear as portas de um endereço ou 2 para escanear uma rede: "))
ip = ''
if (mode == 1):

    protocolo = input("Qual protocolo(TCP/UDP)? ").upper()
    portas_arg = input(
        "Range das portas a serem escaneadas(ex 20:40), deixar vazio para todas: ")
    if len(portas_arg) <= 3:
        portas_arg = "1:65536"


elif (mode == 2):
    _subnet = input("Entre a subrede a ser escaneada(ex: 192.168.1.0/24): ")
    _subnet = _subnet.split("/")
    subnet = _subnet[0]
    mask = int(_subnet[1])
    ports_list = [20, 21, 22, 23, 25, 80, 111, 443, 445,
                  631, 993, 995, 135, 137, 138, 139, 548, 631, 49152, 62078]


def main():
    if(mode == 1):
        ip = input("Entre o IP alvo: ")
        portas = (x for x in range(
            int(portas_arg.split(":")[0]), int(portas_arg.split(":")[1])+1))
        scan(ip, portas)
    elif(mode == 2):
        subnet_lsb = int(subnet.split(".")[3])
        mask_range = 2**(32-mask)
        _ips = (x for x in range(
            subnet_lsb, mask_range+1))
        ips = []
        for ip in _ips:
            ips.append(subnet[0:subnet.rfind(".")+1]+str(ip))

        netscan(mask_range, ips)
    else:
        print("Tente novamente")


def scan_tcp(ip, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
        s.settimeout(0.3)
        if s.connect_ex((ip, port)) == 0:
            banner = socket.getservbyport(port)
            print("{0}/tcp    open  {1}".format(port, banner))
    except:
        pass


def scan_udp(ip, port):
    # print("PORTA: ", port)
    pkt = sr1(IP(dst=ip)/UDP(sport=port, dport=port), timeout=2, verbose=0)
    if pkt == None:
        banner = "Uknown"
        try:
            banner = socket.getservbyport(port, 'udp')
        except:
            pass
            # banner = "placeholder"
        print("{0}/udp   open  {1}".format(port, banner))

    else:
        if pkt.haslayer(UDP):
            banner = "Uknown"
            try:
                banner = socket.getservbyport(port, 'udp')
            except:
                pass
            print("{0}/udp   open  {1}".format(port, banner))


def scan(ip, portas):
    print("-"*23)
    print("PORT      STATE SERVICE")
    print("-"*23)
    if (protocolo == "UDP"):
        for c in portas:
            scan_udp(ip, c)
    else:
        for c in portas:
            scan_tcp(ip, c)


def netscan(mask_range, ips):
    print("-"*35)
    print("Inicializando escaneamento de rede..")
    print("-"*35)
    counter = 0
    for ip in ips:
        for port in ports_list:

            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
                s.settimeout(0.3)
                if s.connect_ex((ip, port)) == 0:
                    counter += 1
                    print("\nhost em {} está ativo".format(ip))
                    break
                s.close()
            except:
                pass

    print("-"*35)
    print("Scan finalizado:{1} hosts ativos de um total de {2} endereços analisados".format(
        counter, mask_range))
    print("-"*35)


if __name__ == '__main__':
    main()
