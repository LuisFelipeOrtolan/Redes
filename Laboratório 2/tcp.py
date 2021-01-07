import asyncio
import random
import time
from tcputils import *
from math import floor


class Servidor:
    def __init__(self, rede, porta):
        self.rede = rede
        self.porta = porta
        self.conexoes = {}
        self.callback = None
        self.rede.registrar_recebedor(self._rdt_rcv)

    def registrar_monitor_de_conexoes_aceitas(self, callback):
        """
        Usado pela camada de aplicação para registrar uma função para ser chamada
        sempre que uma nova conexão for aceita
        """
        self.callback = callback

    def _rdt_rcv(self, src_addr, dst_addr, segment):
        src_port, dst_port, seq_no, ack_no, \
            flags, window_size, checksum, urg_ptr = read_header(segment)

        if dst_port != self.porta:
            # Ignora segmentos que não são destinados à porta do nosso servidor
            return
        if not self.rede.ignore_checksum and calc_checksum(segment, src_addr, dst_addr) != 0:
            print('descartando segmento com checksum incorreto')
            return

        payload = segment[4*(flags>>12):]
        id_conexao = (src_addr, src_port, dst_addr, dst_port)

        if (flags & FLAGS_SYN) == FLAGS_SYN:
            # A flag SYN estar setada significa que é um cliente tentando estabelecer uma conexão nova
            # TODO: talvez você precise passar mais coisas para o construtor de conexão
            conexao = self.conexoes[id_conexao] = Conexao(self, id_conexao, seq_no, dst_addr)
            # TODO: você precisa fazer o handshake aceitando a conexão. Escolha se você acha melhor
            conexao.seq_serv = seq_no
            conexao.ack_serv = seq_no + 1
            conexao.ack_no = conexao.seq_serv + 1
            self.rede.enviar(fix_checksum(make_header(dst_port, src_port, conexao.seq_serv , conexao.ack_serv, FLAGS_SYN + FLAGS_ACK),dst_addr, src_addr), src_addr)
            conexao.seq_no = conexao.seq_no + 1
            conexao.seq_serv = conexao.seq_serv + 1
            if self.callback:
                self.callback(conexao)
        elif id_conexao in self.conexoes:
            # Passa para a conexão adequada se ela já estiver estabelecida
            self.conexoes[id_conexao]._rdt_rcv(seq_no, ack_no, flags, payload)
        else:
            print('%s:%d -> %s:%d (pacote associado a conexão desconhecida)' %
                  (src_addr, src_port, dst_addr, dst_port))


class Conexao:
    def __init__(self, servidor, id_conexao,seq_no, dst_addr):
        self.servidor = servidor
        self.id_conexao = id_conexao
        self.callback = None
        self.seq_no = seq_no
        self.ack_no = None
        self.seq_serv = None
        self.ack_serv = None
        self.end_servidor = dst_addr
        
        self.buffer = None
        self.pos_buffer = None
        self.parte_buffer = 0
        
        self.time_envio = 0
        self.time_recieve = 0
        self.time_total = 0
        self.time_estimated = None
        self.time_dev = 0
        self.time_ack = 0
        self.time_out = 1
        
        self.active = 1
        
        self.timer = asyncio.get_event_loop().call_later(1000, self._exemplo_timer)  # um timer pode ser criado assim; esta linha é só um exemplo e pode ser removida
        self.timer.cancel()   # é possível cancelar o timer chamando esse método; esta linha é só um exemplo e pode ser removida

    def _exemplo_timer(self):
        tam = self.seq_no - self.ack_serv
        if(tam != 0):
            self.time_ack = 0
            if (self.parte_buffer + 1) <= len(self.buffer):
                dados = self.buffer[self.parte_buffer*MSS:(self.parte_buffer+1)*MSS]
            else:
                dados = self.buffer[self.parte_buffer*MSS:]
            if len(dados) <= MSS:
                self.servidor.rede.enviar(fix_checksum(make_header(self.id_conexao[1], self.servidor.porta, self.pos_buffer, self.ack_no, FLAGS_ACK) + dados, self.id_conexao[0], self.end_servidor),self.servidor.porta)
            else:
                self.servidor.rede.enviar(fix_checksum(make_header(self.id_conexao[1], self.servidor.porta, self.pos_buffer, self.ack_no, FLAGS_ACK) + dados[:MSS], self.id_conexao[0], self.end_servidor), self.servidor.porta)
            self.timer = asyncio.get_event_loop().call_later(self.time_out, self._exemplo_timer)

    def _rdt_rcv(self, seq_no, ack_no, flags, payload):
        # TODO: trate aqui o recebimento de segmentos provenientes da camada de rede.
        # Chame self.callback(self, dados) para passar dados para a camada de aplicação após
        # garantir que eles não sejam duplicados e que tenham sido recebidos em ordem.
        if self.active == 0:
            return

        if(self.time_ack == self.ack_serv):
            self.time_recieve = time.time()
            self.time_total = self.time_recieve - self.time_envio
            if self.time_estimated == None:
                self.time_estimated = self.time_total
                self.time_dev = self.time_total/2
            else:
                self.time_estimated = (1-0.125)*self.time_estimated + 0.125*self.time_total
                self.time_dev = (1-0.25)*self.time_dev + 0.25*abs(self.time_total - self.time_estimated)
            self.time_out = self.time_estimated + 4*self.time_dev


        if (flags & FLAGS_FIN) == FLAGS_FIN:
            self.callback(self,b'')
            self.servidor.rede.enviar(fix_checksum(make_header(self.id_conexao[1], self.servidor.porta, self.seq_no, self.ack_no + 1, FLAGS_ACK), self.id_conexao[0], self.end_servidor), self.servidor.porta)  
            self.ack_no = self.ack_no + 1
            return

        if (seq_no == self.ack_no) and (len(payload) > 0):
            self.seq_serv = seq_no
            self.ack_serv = ack_no
            self.ack_no = self.seq_serv + len(payload)
            self.servidor.rede.enviar(fix_checksum(make_header(self.id_conexao[1], self.servidor.porta, self.seq_no, self.ack_no, FLAGS_ACK), self.id_conexao[0], self.end_servidor), self.servidor.porta)
            self.callback(self, payload)


        if ack_no > self.ack_serv:
            self.ack_serv = ack_no
            if self.seq_no > ack_no:
                self.timer = asyncio.get_event_loop().call_later(self.time_out,self._exemplo_timer)
                if len(self.buffer) >= MSS:
                    self.pos_buffer = self.pos_buffer + MSS
                    self.parte_buffer = self.parte_buffer + 1
                else:
                    self.pos_buffer = self.pos_buffer + len(self.buffer)
            else:
                self.timer.cancel()
    # Os métodos abaixo fazem parte da API

    def registrar_recebedor(self, callback):
        """
        Usado pela camada de aplicação para registrar uma função para ser chamada
        sempre que dados forem corretamente recebidos
        """
        self.callback = callback

    def enviar(self, dados):
        """
        Usado pela camada de aplicação para enviar dados
        """
        # TODO: implemente aqui o envio de dados.
        # Chame self.servidor.rede.enviar(segmento, dest_addr) para enviar o segmento
        # que você construir para a camada de rede.
        if self.active == 0:
            return

        self.buffer = dados
        self.pos_buffer = self.seq_no
        self.parte_buffer = 0

        if len(dados) <= MSS:
            self.servidor.rede.enviar(fix_checksum(make_header(self.id_conexao[1], self.servidor.porta, self.seq_no, self.ack_no, FLAGS_ACK) + dados, self.id_conexao[0], self.end_servidor),self.servidor.porta)
            self.time_envio = time.time()
            self.time_ack = self.seq_no
            self.seq_no = self.seq_no + len(dados)
            if self.timer._cancelled == True:
                self.timer = asyncio.get_event_loop().call_later(self.time_out, self._exemplo_timer)
        else:
            for i in range(floor((len(dados)/MSS)) - 1):
                self.servidor.rede.enviar(fix_checksum(make_header(self.id_conexao[1], self.servidor.porta, self.seq_no, self.ack_no, FLAGS_ACK) + dados[i*MSS:((i+1)*MSS)], self.id_conexao[0], self.end_servidor),self.servidor.porta)
                self.time_envio = time.time()
                self.time_ack = self.seq_no
                self.seq_no = self.seq_no + len(dados[i*MSS:((i+1)*MSS)])
                if self.timer._cancelled == True:
                    self.timer = asyncio.get_event_loop().call_later(self.time_out, self._exemplo_timer)
            self.servidor.rede.enviar(fix_checksum(make_header(self.id_conexao[1], self.servidor.porta, self.seq_no, self.ack_no, FLAGS_ACK) + dados[(i+1)*MSS:len(dados)], self.id_conexao[0], self.end_servidor), self.servidor.porta)
            self.time_envio = time.time()
            self.time_ack = self.seq_no
            self.seq_no = self.seq_no + len(dados[(i+1)*MSS:len(dados)])
            if self.timer._cancelled == True:
                self.timer = asyncio.get_event_loop().call_later(self.time_out, self._exemplo_timer)
        pass

    def fechar(self):
        """
        Usado pela camada de aplicação para fechar a conexão
        """
        # TODO: implemente aqui o fechamento de conexão
        self.servidor.rede.enviar(fix_checksum(make_header(self.id_conexao[1], self.servidor.porta, self.seq_no, self.ack_no, FLAGS_FIN), self.id_conexao[0], self.end_servidor), self.servidor.porta)
        self.active = 0
        pass
