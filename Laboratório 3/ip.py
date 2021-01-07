from iputils import *
from tcputils import fix_checksum, str2addr
import struct


class IP:
    def __init__(self, enlace):
        """
        Inicia a camada de rede. Recebe como argumento uma implementação
        de camada de enlace capaz de localizar os next_hop (por exemplo,
        Ethernet com ARP).
        """
        self.callback = None
        self.enlace = enlace
        self.enlace.registrar_recebedor(self.__raw_recv)
        self.ignore_checksum = self.enlace.ignore_checksum
        self.meu_endereco = None

        # Tabelas para controlar o next hop.
        self.cidr = []
        self.hop = []

    def __raw_recv(self, datagrama):
        dscp, ecn, identification, flags, frag_offset, ttl, proto, \
           src_addr, dst_addr, payload = read_ipv4_header(datagrama)

        if dst_addr == self.meu_endereco:
            # atua como host
            if proto == IPPROTO_TCP and self.callback:
                self.callback(src_addr, dst_addr, payload)
        else:
            # atua como roteador
            next_hop = self._next_hop(dst_addr)
            # TODO: Trate corretamente o campo TTL do datagrama
            if ttl - 1 != 0: # Caso ainda haja tempo de vida.
                # Reobtém os dados originais a partir da opereção inversa de quando se lê o datagrama.
                dscpecn = dscp << 2 
                flagfrag = flags << 13
                # Cria um novo datagrama com as informaçẽs originais, mas reduzindo o tempo de vida em 1.
                datagrama = struct.pack('!BBHHHBBH4s4s', 69, dscpecn, len(datagrama), identification, flagfrag, 
                    ttl-1, proto, 0, str2addr(src_addr),str2addr(dst_addr))
                # Corrige o checksum.
                datagrama = datagrama[:-10] + struct.pack('!H',calc_checksum(datagrama)) + datagrama[-8:]
                # Adiciona o payload.
                datagrama = datagrama + payload
                self.enlace.enviar(datagrama, next_hop) # Envia.
            
            else: # Caso não haja mais tempo de vida.
                # Reobtém os dados originais a partir da opereção inversa de quando se lê o datagrama.
                dscpecn = dscp << 2
                flagfrag = flags << 13
                # Cria um novo datagrama para avisar que o tempo de vida acabou.
                new_datagrama = struct.pack('!BBHHHBBH4s4s', 69, dscpecn, 2*len(datagrama)+8+len(payload[:8]), 
                    identification, flagfrag, 64, IPPROTO_ICMP, 0, str2addr(self.meu_endereco),str2addr(src_addr))
                # Corrige o checksum.
                new_datagrama = new_datagrama[:-10] + struct.pack('!H',calc_checksum(new_datagrama)) + new_datagrama[-8:]
                # Adiciona o payload com o datagrama original mais os primeiros 8 bytes.
                resto = struct.pack('!BBHHH', 11,0,0,0,0) + datagrama + payload[:8]
                resto = resto[:-(26+len(payload[:8]))] + struct.pack('!H', calc_checksum(resto)) + resto[-(24+len(payload[:8])):]
                new_datagrama = new_datagrama + resto
                self.enlace.enviar(new_datagrama, next_hop) # Envia.
            


    def _next_hop(self, dest_addr):
        # TODO: Use a tabela de encaminhamento para determinar o próximo salto
        # (next_hop) a partir do endereço de destino do datagrama (dest_addr).
        # Retorne o next_hop para o dest_addr fornecido.
        daddr = dest_addr.split('.') # Separa o endereço atual em 4 casas.
        endr = ''
        for i in range(len(daddr)):
            endr = endr + str(format(int(daddr[i]),'08b')) # Transforma em um grande número binário.

        curr_best = -1 # Tamanho do maior endereço combinado até agora.

        for item in self.cidr: # Para cada um dos itens na tabela,
            validos = int(item.split('/')[1]) # Obtém quantos números são válidos no endereço.
            if validos > curr_best: # Se o número de válidos for maior que o atual (evita olhar para itens que não ajudam).
                endereco = item.split('/')[0].split('.') # Separa o endereço em 4 casas.
                codigo = ''
                for i in range(len(endereco)):
                    codigo = codigo + str(format(int(endereco[i]),'08b')) # Transforma em um grande número binário.
                codigo = codigo[0:validos] # Remove os números não válidos.
                if endr[0:validos] == codigo[0:validos]: # Se há um casamento exato dos números válidos,
                    curr_best = validos # Guarda como nova melhor solução.
                    solucao = item

        if curr_best >= 0: # Se existir uma solução,
            return self.hop[self.cidr.index(solucao)] # Retorna o new_hop.

        else: # Caso não exista solução,
            return None # Retorna vazio.

        pass

    def definir_endereco_host(self, meu_endereco):
        """
        Define qual o endereço IPv4 (string no formato x.y.z.w) deste host.
        Se recebermos datagramas destinados a outros endereços em vez desse,
        atuaremos como roteador em vez de atuar como host.
        """
        self.meu_endereco = meu_endereco

    def definir_tabela_encaminhamento(self, tabela):
        """
        Define a tabela de encaminhamento no formato
        [(cidr0, next_hop0), (cidr1, next_hop1), ...]

        Onde os CIDR são fornecidos no formato 'x.y.z.w/n', e os
        next_hop são fornecidos no formato 'x.y.z.w'.
        """
        self.cidr = []
        self.hop = []

        for i in range(len(tabela)): # Para cada item na tabela,
            if tabela[i][0] in self.cidr: # Se o endereço já estiver na tabela,
                self.hop[self.cidr.index(tabela[i][0])] = tabela[i][1] # Atualiza o novo hop.
            else: # Caso contrário, adiciona na lista.
                self.cidr.append(str(tabela[i][0]))
                self.hop.append(str(tabela[i][1]))
        # TODO: Guarde a tabela de encaminhamento. Se julgar conveniente,
        # converta-a em uma estrutura de dados mais eficiente.
        pass

    def registrar_recebedor(self, callback):
        """
        Registra uma função para ser chamada quando dados vierem da camada de rede
        """
        self.callback = callback

    def enviar(self, segmento, dest_addr):
        """
        Envia segmento para dest_addr, onde dest_addr é um endereço IPv4
        (string no formato x.y.z.w).
        """
        next_hop = self._next_hop(dest_addr)
        # TODO: Assumindo que a camada superior é o protocolo TCP, monte o
        # datagrama com o cabeçalho IP, contendo como payload o segmento.
        # Cria o datagrama.
        datagrama = struct.pack('!BBHHHBBH4s4s', 69, 0, 20 + len(segmento), 10, 0, 64, IPPROTO_TCP, 0, 
            str2addr(self.meu_endereco),str2addr(dest_addr))
        # Corrige o checksum.
        datagrama = datagrama[:-10] + struct.pack('!H',calc_checksum(datagrama)) + datagrama[-8:]
        # Adiciona o payload.
        datagrama = datagrama + segmento
        # Envia.
        self.enlace.enviar(datagrama, next_hop)
