#!/usr/bin/env python
# -*- coding: utf-8 -*-

__author__ = "Adrien Pujol - http://www.crashdump.fr/"
__copyright__ = "Copyright 2013, Adrien Pujol"
__license__ = "Mozilla Public License"
__version__ = "0.2"
__email__ = "adrien.pujol@crashdump.fr"
__status__ = "Development"
__doc__ = "Check a TLS certificate validity."

import argparse
import socket
import ssl
from datetime import datetime

CA_CERTS = "/etc/ssl/certs/ca-certificates.crt"


def exit_error(errcode, errtext):
    print errtext
    exit(errcode)


def check_ssl_validity_hostname(cert, hostname):
    ''' Return True if valid. False is invalid '''
    if 'subjectAltName' in cert:
        for typ, val in cert['subjectAltName']:
            # Wilcard
            if typ == 'DNS' and val.startswith('*'):
                if val[2:] == hostname.split('.', 1)[1]:
                    return True
            # Normal hostnames
            elif typ == 'DNS' and val == hostname:
                return True
    else:
        return False


def check_ssl_expiration(cert):
    ''' Return the numbers of day before expiration. False if expired. '''
    if 'notAfter' in cert:
        try:
            expire_date = datetime.strptime(cert['notAfter'],
                                            "%b %d %H:%M:%S %Y %Z")
        except:
            exit_error(1, 'Certificate date format unknow.')
        expire_in = expire_date - datetime.now()
        if expire_in.days > 0:
            return expire_in.days
        else:
            return False


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('host', help='specify an host to connect to')
    parser.add_argument('-p', '--port', help='specify a port to connect to',
                        type=int, default=443)
    args = parser.parse_args()

    # Check the DNS name
    try:
        socket.getaddrinfo(args.host, args.port)[0][4][0]
    except socket.gaierror as e:
        exit_error(1, e)

    # Connect to the host and get the certificate
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ssl_sock = ssl.wrap_socket(sock, cert_reqs=ssl.CERT_REQUIRED,
                               ca_certs=CA_CERTS,
                               ciphers="HIGH:-aNULL:-eNULL:-PSK:RC4-SHA:RC4-MD5")

    try:
        ssl_sock.connect((args.host, args.port))
    except ssl.SSLError as e:
        exit_error(1, e)

    cert = ssl_sock.getpeercert()

    if not check_ssl_validity_hostname(cert, args.host):
        print 'Error: Hostname does not match!'

    print check_ssl_expiration(cert)

    sock = ssl_sock.unwrap()
    sock.close()


if __name__ == "__main__":
    main()