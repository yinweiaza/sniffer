# coding: utf-8
import  socket


class Sniffer(object):
    def __init__(self):
        host = socket.gethostbyname(socket.gethostname())
        sock = socket.socket(socket.AF_INET,socket.SOCK_RAW, socket.IPPROTO_IP)
