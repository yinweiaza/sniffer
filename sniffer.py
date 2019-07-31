# coding: utf-8
import socket


class PrepareSock(object):
    def __init__(self):
        host = socket.gethostbyname(socket.gethostname())
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)     # 原始套接字;
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)          # 打开地址复用功能；
        sock.bind((host, 0))                                         # 绑定地址，公共接口；
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)        # 设置数据保护IP头部
        sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)             # 开启混杂模式；
        self.sock = sock

    def __enter__(self):
        return  self.sock

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)           # 关闭混杂模式;


class Sniffer(object):
    def __init__(self):
        pass

    def sniffer(self, count, buffsize = 65535, showPort = False, showRawData = False):
        with PrepareSock() as sock:
            for i in xrange(count):
                pakege = sock.recvfrom(buffsize)
                self.printPacket(pakege, showPort, showRawData)

    def printPacket(self, package, showPort, showRawData):
        dataIndex = 0
        headerIndex = 1
        ipAddressIndex = 0
        portIndex = 1

        print 'IP：', package[headerIndex][ipAddressIndex]
        if showPort:
            print 'Port:', package[headerIndex][portIndex]
        if showRawData:
            print 'Data:', package[dataIndex]


if __name__ == "__main__":
    sniffer = Sniffer()
    sniffer.sniffer(50, 65535, True, True)