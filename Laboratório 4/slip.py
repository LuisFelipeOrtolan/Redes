# Função que realiza o split mas mantém o delimitador.
# Créditos:
# https://stackoverflow.com/questions/2136556/in-python-how-do-i-split-a-string-and-keep-the-separators/61436083#61436083
# Input: Uma string s e um delimitador.
# Output: Um vetor com a string dividida (incluindo o delimitador) toda vez que houve um delimitador.
def splitkeep(s, delimiter):
    split = s.split(delimiter)
    return [substr + delimiter for substr in split[:-1]] + [split[-1]]


class CamadaEnlace:
    ignore_checksum = False

    def __init__(self, linhas_seriais):
        """
        Inicia uma camada de enlace com um ou mais enlaces, cada um conectado
        a uma linha serial distinta. O argumento linhas_seriais é um dicionário
        no formato {ip_outra_ponta: linha_serial}. O ip_outra_ponta é o IP do
        host ou roteador que se encontra na outra ponta do enlace, escrito como
        uma string no formato 'x.y.z.w'. A linha_serial é um objeto da classe
        PTY (vide camadafisica.py) ou de outra classe que implemente os métodos
        registrar_recebedor e enviar.
        """
        self.enlaces = {}
        self.callback = None
        # Constrói um Enlace para cada linha serial
        for ip_outra_ponta, linha_serial in linhas_seriais.items():
            enlace = Enlace(linha_serial)
            self.enlaces[ip_outra_ponta] = enlace
            enlace.registrar_recebedor(self._callback)

    def registrar_recebedor(self, callback):
        """
        Registra uma função para ser chamada quando dados vierem da camada de enlace
        """
        self.callback = callback

    def enviar(self, datagrama, next_hop):
        """
        Envia datagrama para next_hop, onde next_hop é um endereço IPv4
        fornecido como string (no formato x.y.z.w). A camada de enlace se
        responsabilizará por encontrar em qual enlace se encontra o next_hop.
        """
        # Encontra o Enlace capaz de alcançar next_hop e envia por ele
        self.enlaces[next_hop].enviar(datagrama)

    def _callback(self, datagrama):
        if self.callback:
            self.callback(datagrama)


class Enlace:
    def __init__(self, linha_serial):
        self.linha_serial = linha_serial
        self.linha_serial.registrar_recebedor(self.__raw_recv)
        self.comandos = b''

    def registrar_recebedor(self, callback):
        self.callback = callback

    def enviar(self, datagrama):
        # TODO: Preencha aqui com o código para enviar o datagrama pela linha
        # serial, fazendo corretamente a delimitação de quadros e o escape de
        # sequências especiais, de acordo com o protocolo CamadaEnlace (RFC 1055).
        aux = b'' # Auxiliar para criar o datagrama.
        for i in range(len(datagrama)): # Para cada caracter do datagrama.
            if datagrama[i] == 192: # datagrama[i] == b'\xc0'
                aux = aux + b'\xdb' + b'\xdc' # Substitui b'\xc0' por b'\xdbxdc'
            elif datagrama[i] == 219: # datagrama[i] == b'\xdb'
                aux = aux + b'\xdb' + b'\xdd' # Substitui b'\xdb' por b'\xdbxdd'
            else: # Caso não seja nenhum destes,
                aux = aux + bytes([datagrama[i]]) # Só copia o caracter do datagrama.
        datagrama = b'\xc0' + aux + b'\xc0' # Insere no começo e no final o caracter que indica início/término.
        self.linha_serial.enviar(datagrama) # Envia o datagrama com os caracteres corrigidos.
        pass

    def __raw_recv(self, dados):
        # TODO: Preencha aqui com o código para receber dados da linha serial.
        # Trate corretamente as sequências de escape. Quando ler um quadro
        # completo, repasse o datagrama contido nesse quadro para a camada
        # superior chamando self.callback. Cuidado pois o argumento dados pode
        # vir quebrado de várias formas diferentes - por exemplo, podem vir
        # apenas pedaços de um quadro, ou um pedaço de quadro seguido de um
        # pedaço de outro, ou vários quadros de uma vez só.

        s = splitkeep(dados, b'\xc0') # Separa os dados.

        for entrada in s: # Para cada uma das entradas no vetor,
            if len(entrada) > 0: # Se houver algum dado,
                if entrada[len(entrada) - 1] == 192: # Se for b'xc0', indica final de comando.
                    entrada = entrada[:-1] # Remove o caracter que indica final de comando.
                    self.comandos = self.comandos + entrada # Adiciona no que tiver sobrado do comando.
                    if len(self.comandos) > 0: # Se houver comando a ser dado,
                        self.comandos = self.comandos.replace(b'\xdb\xdc', b'\xc0') # Desfaz as substituições.
                        self.comandos = self.comandos.replace(b'\xdb\xdd', b'\xdb')
                        # Lida com exceção de sobrar dados.
                        try: 
                            self.callback(self.comandos)
                        except:
                            import traceback
                            traceback.print_exc()
                        finally:
                            self.comandos = b''
                            entrada = b''
                    self.comandos = b'' # Comando finalizado, então limpa o buffer de comandos.
                else: # Caso o comando ainda não tenha sido finalizado,
                    self.comandos = self.comandos + entrada # Guarda o que veio e espere um finalizador.

        pass