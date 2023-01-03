# from template import build_template
# from utils import check_args, PORTOCOL
import socket
import struct
import threading
import time
import lzma
import zstandard as zstd
import os

class RDT():
    def __init__(self, MSS=1024, TimeOut=1, Test_mode=True, Verbose=False                                                                                                                                                                                                                    ) -> None:
        self.MSS = MSS
        self.Test_mode = Test_mode
        self.Verbose = Verbose
        self.HEAD_SZ = 4 * len(struct.pack('!i', 0))
        self.PKT_SZ = self.MSS + self.HEAD_SZ
        self.TimeOut = TimeOut

        if (Test_mode):
            self.send_time = 0
            self.success_time = 0
            self.rtt_list = []

    def start_timer(self):
        if (self.Test_mode):
            self.time_start = time.time()
        self.timer = threading.Timer(self.TimeOut, self.timeout)
        self.timer.setDaemon(True)
        self.timer.start()

    def stop_timer(self):
        if (self.Test_mode):
            self.rtt_list.append(time.time() - self.time_start)
        self.timer.cancel()

    def timeout(self):
        self.inform('[Timeout]')
        self.stop_timer()
        self.resend()
        self.start_timer()

    def calc_checksum(self, pkt):
        assert (isinstance(pkt['DATA'], bytes))
        check_sum = pkt['SEQ_N'] + pkt['ACK_N']
        check_sum += sum(pkt['DATA'])
        return check_sum

    def init_pkt(self):
        pkt = {}
        pkt['SEQ_N'] = 0
        pkt['ACK_N'] = 0
        pkt['PKG_LEN'] = 0
        pkt['DATA'] = bytearray(self.MSS)
        pkt['CHECK_SUM'] = 0
        return pkt

    def make_pkt(self, seq_num, ack_num, pkg_len, payload: bytes) -> dict:
        pkt = self.init_pkt()
        pkt['SEQ_N'] = seq_num
        pkt['ACK_N'] = ack_num
        pkt['PKG_LEN'] = pkg_len
        pkt['DATA'][0:len(payload)] = payload
        pkt['DATA'] = bytes(pkt['DATA'])
        pkt['CHECK_SUM'] = self.calc_checksum(pkt)
        return pkt

    def get_pkt_num(self, content: bytes):
        length = len(content)

        last = 0 if length % self.MSS == 0 else 1
        pkt_num = length // self.MSS + last
        return pkt_num

    def check_pkt(self, pkt: dict) -> bool:
        return pkt['CHECK_SUM'] == self.calc_checksum(pkt)

    def is_ack(self, pkt: dict, ack_num: int) -> bool:
        return pkt['SEQ_N'] < 0 and pkt['ACK_N'] == ack_num

    def is_seq(self, pkt: dict, seq_num: int) -> bool:
        return pkt['ACK_N'] < 0 and pkt['SEQ_N'] == seq_num

    def encoder_pkt(self, pkt: dict) -> bytes:
        head = struct.pack('!4i', pkt['SEQ_N'], pkt['ACK_N'], pkt['PKG_LEN'], pkt['CHECK_SUM'])
        raw_bytes = head + pkt['DATA']
        return raw_bytes

    def decode_pkt(self, raw_bytes: bytes) -> dict:
        pkt = self.init_pkt()
        pkt['DATA'] = raw_bytes[-self.MSS:]
        head = raw_bytes[:-self.MSS]
        pkt['SEQ_N'], pkt['ACK_N'], pkt['PKG_LEN'], pkt['CHECK_SUM'] = struct.unpack('!4i', head)
        return pkt

    def send_pkt(self, pkt: dict):
        self.inform("Send Pkt: Seq[{:d}] | ACK[{:d}]".format(pkt['SEQ_N'], pkt['ACK_N']))
        raw_bytes = self.encoder_pkt(pkt)
        self.udt_send(raw_bytes)

    def recv_pkt(self) -> dict:
        raw_data = self.udt_recv()
        pkt = self.decode_pkt(raw_data)
        return pkt

    def send_ack(self, ack_num: int):
        pkt = self.make_pkt(-1, ack_num, -1, b'ACK')
        self.send_pkt(pkt)

    def send(self, content: bytes):
        raise NotImplementedError

    def recv(self):
        raise NotImplementedError

    def resend(self):
        raise NotImplementedError

    def udt_send(self, message):
        raise NotImplementedError

    def udt_recv(self):
        raise NotImplementedError

    def add_send_time(self, n):
        if (self.Test_mode):
            self.send_time += n

    def add_success_time(self, n):
        if (self.Test_mode):
            self.success_time += n

    def inform(self, string):
        if (self.Verbose):
            print(string)

    def print_test_result(self):
        assert (self.Test_mode)
        loss_rate = (1 - self.success_time / self.send_time) * 100
        avg_rtt = (sum(self.rtt_list) / len(self.rtt_list)) * 1000
        print(f"Send Times: {self.send_time} | Success Times: {self.success_time}")
        print("Actual Loss Rate: {:.2f} %".format(loss_rate))
        print("Avg RTT: {:.2f}ms".format(avg_rtt))


class altBit(RDT):
    def __init__(self) -> None:
        super(altBit, self).__init__()
        self.state = 0

    def change_state(self):
        # AltBit toggle state
        self.state = int(1 - self.state)

    def resend(self):
        self.send_pkt(self.pkt_send)
        self.add_send_time(1)

    def send(self, content: bytes) -> None:
        pkt_num = self.get_pkt_num(content)
        self.inform(f"Total Pkt Num = {pkt_num}")
        offset = 0

        for i in range(pkt_num):
            self.inform(f"Sending Pkt Num = {i + 1}")
            self.add_send_time(1)
            self.pkt_send = self.make_pkt(self.state, -1, pkt_num - i - 1, content[offset:offset + self.MSS])
            self.send_pkt(self.pkt_send)
            self.start_timer()
            pkt_recv = self.recv_pkt()
            self.stop_timer()

            if (self.check_pkt(pkt_recv) and self.is_ack(pkt_recv, self.state)):
                self.inform(f"Recv Right ACK{self.state}")
                self.add_success_time(1)
                self.change_state()
            else:
                self.inform(f"Recv Wrong ACK, resend Seq{self.state}")
                self.resend()
                self.start_timer()

            offset += self.MSS

        if (self.Test_mode):
            self.print_test_result()

    def recv(self) -> list:
        result = None
        while (result is None):
            pkt = self.recv_pkt()
            if (self.check_pkt(pkt) and self.is_seq(pkt, self.state)):
                self.send_ack(pkt['SEQ_N'])
                self.change_state()
                result = [pkt]
            else:
                self.send_ack(not self.state)

        return result


class goBackN(RDT):
    def __init__(self, window_len=8) -> None:
        super(goBackN, self).__init__()
        self.sender_buffer = []
        self.window_len = window_len
        self.left_side = 0
        self.right_side = 0
        self.seq_n = -1
        self.ack_n = 0
        self.UPPER_N = self.window_len + 1
        # window = [left_side, right_size）

    def is_ack(self, pkt: dict):
        return pkt['SEQ_N'] < 0 and pkt['ACK_N'] != self.seq_n

    def change_state(self, step: int):
        self.left_side += step
        self.right_side = min(self.right_side + step, self.pkt_num)
        self.seq_n = (self.seq_n + step) % self.UPPER_N

    def save_to_buffer(self, pkt_num: int, content: bytes) -> None:
        offset = 0
        seq_n = 0
        for i in range(pkt_num):
            pkt_send = self.make_pkt(seq_n, -1, pkt_num - i - 1, content[offset:offset + self.MSS])
            self.sender_buffer.append(pkt_send)
            seq_n = (seq_n + 1) % self.UPPER_N
            offset += self.MSS

    def send_range(self, left, right):
        idx = left
        while (idx != right):
            pkt_send = self.sender_buffer[idx]
            self.add_send_time(1)
            self.send_pkt(pkt_send)
            idx += 1

    def resend(self):
        self.send_range(self.left_side, self.right_side)

    def send(self, content: bytes) -> None:
        self.pkt_num = self.get_pkt_num(content)
        self.right_side = min(self.left_side + self.window_len, self.pkt_num)
        self.inform(f"Total Pkt Num = {self.pkt_num}")
        self.save_to_buffer(self.pkt_num, content)

        self.send_range(self.left_side, self.right_side)
        self.start_timer()

        while (self.left_side != self.right_side):
            pkt_recv = self.recv_pkt()

            if (self.check_pkt(pkt_recv) and self.is_ack(pkt_recv)):
                self.inform(f"Recv Right ACK{pkt_recv['ACK_N']}")
                self.stop_timer()
                step = (pkt_recv['ACK_N'] - self.seq_n) % self.UPPER_N
                if (step):
                    self.add_success_time(step)
                    send_step = min(step, self.pkt_num - self.right_side)
                    self.send_range(self.right_side, self.right_side + send_step)
                    self.start_timer()
                    self.change_state(step)
            else:
                self.inform(f"Recv Wrong ACK{pkt_recv['ACK_N']}, Dropping")

        if (self.Test_mode):
            self.print_test_result()

    def recv(self) -> list:
        result = None
        while (result is None):
            pkt_recv = self.recv_pkt()
            if (self.check_pkt(pkt_recv) and self.is_seq(pkt_recv, self.ack_n)):
                self.inform(f"Recv Right Seq{pkt_recv['SEQ_N']}")
                self.send_ack(pkt_recv['SEQ_N'])
                self.ack_n = (self.ack_n + 1) % self.UPPER_N
                result = [pkt_recv]
            else:
                last_ack = (self.ack_n - 1) % self.UPPER_N
                self.inform(f"Recv Wrong Seq{pkt_recv['SEQ_N']}, resend ACK{last_ack}")
                self.send_ack(last_ack)

        return result


class selRepeat(RDT):
    def __init__(self, window_len=50) -> None:
        super(selRepeat, self).__init__()
        self.window_len = window_len
        self.sender_buffer = []
        self.receiver_buffer = [0] * self.window_len
        self.sender_mark = [0] * self.window_len
        self.receiver_mark = [0] * self.window_len
        self.pkg_unreceived = None
        self.left_side = 0
        self.right_side = 0
        self.seq_n = -1
        self.ack_n = 0
        self.UPPER_N = 2 * self.window_len
        # window = [left_side, right_size）

    def is_ack(self, pkt: dict):
        return pkt['SEQ_N'] < 0 and pkt['ACK_N'] != self.seq_n

    def change_state(self, step: int):
        self.left_side += step
        self.right_side = min(self.right_side + step, self.pkt_num)
        self.seq_n = (self.seq_n + step) % self.UPPER_N

    def save_to_buffer(self, pkt_num: int, content: bytes) -> None:
        offset = 0
        seq_n = 0
        for i in range(pkt_num):
            pkt_send = self.make_pkt(seq_n, -1, self.pkt_num - i - 1, content[offset:offset + self.MSS])
            self.sender_buffer.append(pkt_send)
            seq_n = (seq_n + 1) % self.UPPER_N
            offset += self.MSS

    def send_range(self, left, right):
        idx = left
        while (idx != right):
            pkt_send = self.sender_buffer[idx]
            self.add_send_time(1)
            self.send_pkt(pkt_send)
            idx += 1

    def resend(self):
        resend_pkt = self.sender_buffer[self.left_side]
        self.send_pkt(resend_pkt)
        self.add_send_time(1)

    def mark_pkt(self, buffer, offset):
        buffer[offset] = 1

    def get_window_shift(self, buffer):
        idx = 0
        while (idx != self.window_len and buffer[idx]):
            idx += 1
        return idx

    def send(self, content: bytes) -> None:
        assert (len(self.sender_buffer) == 0)
        self.pkt_num = self.get_pkt_num(content)
        self.right_side = min(self.left_side + self.window_len, self.pkt_num)
        self.inform(f"Total Pkt Num = {self.pkt_num}")
        self.save_to_buffer(self.pkt_num, content)

        self.send_range(self.left_side, self.right_side)
        self.start_timer()

        while (self.left_side != self.right_side):
            pkt_recv = self.recv_pkt()

            if (self.check_pkt(pkt_recv) and self.is_ack(pkt_recv)):
                self.inform(f"Recv Right ACK{pkt_recv['ACK_N']}")
                offset = (pkt_recv['ACK_N'] - self.seq_n - 1) % self.window_len
                self.mark_pkt(self.sender_mark, offset)
                step = self.get_window_shift(self.sender_mark)

                if (step):
                    self.add_success_time(step)
                    self.stop_timer()
                    send_step = min(step, self.pkt_num - self.right_side)
                    self.send_range(self.right_side, self.right_side + send_step)
                    self.sender_mark = self.sender_mark[step:] + [0] * step
                    self.start_timer()
                    self.change_state(step)

            else:
                self.inform(f"Recv Wrong ACK{pkt_recv['ACK_N']}, Dropping")

        if (self.Test_mode):
            self.print_test_result()

    def recv(self) -> list:
        result = None
        while (result is None):
            pkt_recv = self.recv_pkt()
            if (self.check_pkt(pkt_recv) and (
                    self.pkg_unreceived == None or pkt_recv['PKG_LEN'] <= self.pkg_unreceived)):
                self.inform(f"Recv Right Seq{pkt_recv['SEQ_N']}")
                self.send_ack(pkt_recv['SEQ_N'])

                if (self.pkg_unreceived is None):
                    self.pkg_unreceived = pkt_recv['PKG_LEN']

                offset = self.pkg_unreceived - pkt_recv['PKG_LEN']
                self.mark_pkt(self.receiver_mark, offset)
                self.receiver_buffer[offset] = pkt_recv

                step = self.get_window_shift(self.receiver_mark)
                if (step):
                    self.pkg_unreceived -= step
                    right_step = min(step, self.pkg_unreceived)
                    self.ack_n = (self.ack_n + right_step) % self.UPPER_N
                    result = self.receiver_buffer[:step]
                    self.receiver_mark = self.receiver_mark[step:] + [0] * step
                    self.receiver_buffer = self.receiver_buffer[step:] + [0] * step

            else:
                self.inform(f"Recv Wrong Seq{pkt_recv['SEQ_N']}, resend ACK{pkt_recv['SEQ_N']}")
                self.send_ack(pkt_recv['SEQ_N'])

        return result


PORTOCOL = {
    'ab': altBit,
    'gbn': goBackN,
    'sr': selRepeat
}


def check_args(argv):
    if(len(argv) != 2):
        print(f"Usage: python {argv[0]} <portocol>")
        return False
    if(argv[1] not in PORTOCOL.keys()):
        print("「Support Portocols」:")
        for portocol in list(PORTOCOL.keys()):
            print(f'- {portocol}')
        return False
    return True


def build_template(input_class):
    class Template(input_class):
        def __init__(self, IP, DIP, SEND_PORT, RECV_PORT) -> None:
            super(Template, self).__init__()
            self.UDP_IP = DIP
            self.UDP_SEND_PORT = SEND_PORT
            self.UDP_RECV_PORT = RECV_PORT
            self.sock = socket.socket(socket.AF_INET,  # Internet
                                      socket.SOCK_DGRAM)  # UDP
            self.sock.bind((IP, RECV_PORT))

        def __repr__(self) -> str:
            IP = "UDP target IP: %s" % self.UDP_IP
            SEND_PORT = "UDP target port: %s" % self.UDP_SEND_PORT
            RECV_PORT = "UDP target port: %s" % self.UDP_RECV_PORT
            return "\n".join([IP, SEND_PORT, RECV_PORT])

        '''
        Sending by UDP
            Unreliable Data Transmisson
        '''

        def udt_send(self, message):
            assert (isinstance(message, bytes))
            self.sock.sendto(message, (self.UDP_IP, self.UDP_SEND_PORT))

        def udt_recv(self):
            # print('2')
            # return self.sock.recv(self.MSS)
            return self.sock.recv(self.PKT_SZ)

        def close(self):
            self.sock.close()

    return Template


def build_receiver(portocol):
    class Receiver(build_template(portocol)):
        def __init__(self, IP, DIP, SEND_PORT, RECV_PORT) -> None:
            super().__init__(IP, DIP, SEND_PORT, RECV_PORT)
            self.buffer = []
            
        def Recv(self):
            while True:
                data = self.recv()
                self.buffer.extend(data)
                # 如果最后一行长度为0则开始回送
                if(data[-1]['PKG_LEN'] == 0):
                    self.to_app_layer()
                    break
            
        def to_app_layer(self):
            print("[Data Received]")
            result = ''
            # f = open('output.bin', 'wb')
            for pkt in self.buffer:
                # f.write(pkt['DATA'])
                result += pkt['DATA'].decode('latin1')
            result = result.strip('\0')
            print(f"Len: {len(result)}")
            # self.save_file('./output.bin', result.encode('latin1'))
            # self.save_file('./output.bin.xz', result.encode('latin1'))
            # self.decompress1('./output.bin.xz','./output.bin')
            self.save_file('./output.bin.zst', result.encode('latin1'))
            self.decompress2('./output.bin.zst','./output.bin')
            os.remove('./output.bin.zst')
            # f.close()

        def save_file(self, filePath, data):
            with open(filePath, 'wb') as f:
                f.write(data)

        def decompress1(self, xzpath, orgpath):
            with open(orgpath,'wb') as pw:
                zf = lzma.open(xzpath, mode = 'rb') #打开压缩文件
                data=zf.read()  # 解压文件
                pw.write(data)  # 写解压缩文件
                zf.close()  
        def decompress2(self, zstpath, orgpath):
            dctx = zstd.ZstdDecompressor()
            with open(zstpath, 'rb') as ifh, open(orgpath, 'wb') as ofh:
                dctx.copy_stream(ifh, ofh)

    
    return Receiver


if __name__ == "__main__":
    # if(check_args(sys.argv) is False):
    #     sys.exit(1)
        
    ip = '192.168.78.132'
    dip = '192.168.78.133'
    send_port = 8889
    recv_port = 8888
        
    Receiver = build_receiver(PORTOCOL['sr'])  # 创建接收环境
    receiver = Receiver(ip, dip, send_port, recv_port)  # 绑定端口，等待接收
    print("Initialized, Wait For Data~")
    receiver.Recv()  # 调用Receiver类的Recv方法
    receiver.close()
        