"""
Raw socket permite fazer o bypass do transporte
de pacote pela rede(ou seja, assim que sai da placa
de rede, ele pode ir direto ao usuário, ao invés de se
guir a pilha de protocolos).

Para isso, utiliza-se a interface AF_PACKET, que é de baixo
nível para se trabalhar com pacotes vindos da rede.
Todos os pacotes estarão íntegros com seus cabeçalhos
e segmentos de dados.

-- Logo, o raw_socket_sniffer fareja a rede afim de encontrar requisicoes http (porta 80)

********** O PACOTE AF_PACKET DO MODULO SOCKET FUNCIONA APENAS NO LINUX, its work only in linux ************

"""
import socket
import argparse as ap
import sys
from platform import system

if system() != "Linux":
    print("Its only available on linux")
    sys.exit(0)


def str_ethernet(ethernet: bytes) -> str:
    """
    Converte o mac address
    de bytes para string
    [de cada endereço passado]
    """
    ethernet: str = ethernet.hex().upper()
    str_converted = ""
    for char in range(0, 10, 2):  # mac adress são no formato 00:xx:00:xx:00:xx (6 itens)
        str_converted += f"{ethernet[char:char + 2]}:"
    return str_converted


def parse_header_ethernet(header: bytes) -> bool:
    """
    Disseca o cabeçalho
    do pacote ethernet
    para obter informações
    """
    ether_dst: bytes = header[:6]  # 5 primeiros bytes do pacote ethernet refere-se ao destion e etc
    ether_origin: bytes = header[6: 12]
    ether_type: bytes = header[12:]
    print("---[ ETHERNET ]---")
    print(f"   From:\t{str_ethernet(ether_dst)}")
    print(f"   To:\t{str_ethernet(ether_origin)}")
    return ether_type == b"\x08\x00"  # ethertype do protocolo ip


def parse_ip(header: bytes) -> str:
    """
    Converte o ip recebido
    e exibe o tipo do protocolo
    de comunicacao utilizado
    """
    type: bytes = header[9:10]
    origin: bytes = header[12: 16]
    to: bytes = header[16: 20]
    print("---[ IP ]---")
    print(f"   From:\t{socket.inet_ntoa(origin)}")  # funcao que já converte de byte para str
    print(f"   To:\t{socket.inet_ntoa(to)}")
    if type == b"x06":
        return "TCP"
    elif type == b"x11":
        return "UDP"
    else:
        return "Missing type"


def parse_tcp(header: bytes) -> bool:
    """
    Faz parse do cabeçalho na
    regiao do protocolo e verifica
    quais as portas utilizadas
    """
    port_origin: int = int.from_bytes(header[:2], byteorder="big")
    port_to: int = int.from_bytes(header[2:4], byteorder="big")
    print("---[ TCP ]---")
    print(f"   From port:\t{port_origin}")
    print(f"   To port:\t{port_to}")
    return port_origin == 80  # http


def parse_udp(header: bytes) -> bool:
    """
    Faz parse do cabeçalho na
    regiao do protocolo e verifica
    quais as portas utilizadas
    """
    print("---[ UDP ]---")
    print(f"   From port:\t{int.from_bytes(header[:2], byteorder='big')}")
    print(f"   To port:\t{int.from_bytes(header[2:4], byteorder='big')}")
    return int.from_bytes(header[:2], byteorder='big') == 80  # http


def main() -> None:
    raw_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htonl(0x800))
    while True:
        raw_packet = raw_socket.recvfrom(2048)[0]
        print("\n\nReceived:")
        if parse_header_ethernet(raw_packet[:14]):
            type_ = parse_ip(raw_packet[14:34])  # 20 bytes ip
            if type_:
                if type_ == "UDP":
                    parse_udp(raw_packet[34:42])
                elif type_ == "TCP":
                    if parse_tcp(raw_packet[34:54]):  # se for porta 80,printa o q vier do http
                        print(raw_packet[54:])


def args_() -> None:
    """Trata a linha de comandos"""
    arg = ap.ArgumentParser(description="Sniffer the network [http]")
    arg.add_argument("-run", metavar="start", help="start the script", type=str, required=True)
    args = arg.parse_args()
    if args.run:
        main()


if __name__ == '__main__':
    args_()
