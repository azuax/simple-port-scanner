#!/usr/bin/python3

from termcolor import colored
from threading import Thread
import optparse
import socket


def connect_scan(ip, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if not s.connect_ex((ip, port)):
            banner = s.recv(1024)
            print(colored('[+] {}/tcp OPEN {}'.format(port, banner.decode('utf-8').strip()), 'green'))
    except Exception as e:
        # print(colored('[-] There was a problem:\n{}'.format(e), 'red'))
        pass
    finally:
        s.close()


def port_scan(host, ports):
    try:
        ip = socket.gethostbyname(host)
    except Exception as e:
        print(colored('[-] Host doesn\'t exist', 'red'))
        return 0

    if '-' not in ports:
        ports = '-' + str(ports)

    r_ini, r_end = ports.split('-')

    r_ini = int(r_ini or 1)
    r_end = int(r_end)

    socket.setdefaulttimeout(1)
    print('[*] Scanning ports')
    for i in range(r_ini, r_end + 1):
        t = Thread(target=connect_scan, args=(ip, i))
        t.start()


def main():
    parser = optparse.OptionParser('Usage: ./main.py -H <host> -p <port-range>')
    parser.add_option('-H', dest='host', type='string', help='Target host')
    parser.add_option('-p', dest='ports', type='string', help='Target ports')
    (options, args) = parser.parse_args()
    host = options.host
    ports = options.ports
    if not host or not ports:
        print(parser.usage)
        exit(0)

    port_scan(host, ports)


if __name__ == '__main__':
    main()
