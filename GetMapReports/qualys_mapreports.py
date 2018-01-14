#!/usr/bin/env python

"""
17/12/2017
"""

import sys
import contextlib
import OpenSSL.crypto
import requests
from requests.auth import HTTPBasicAuth
import tempfile
import xml.etree.ElementTree as ET
import getpass
import time
import socket #socket excpetion

__author__ = 'David Alvarez @dalvarez_s'
__version__ = '0.2'
__doc__ = 'Connects to Qualys API. Get list of Map reports finished and extract hosts without DNSname ' \
          'UseCase: Useful for identifying live hosts without DNSname'

#ToDo: Parallel HTTP requests


QUSER = None
QPASSWD = None
QCERT_PASSWD = None
#QUSER = 'user'
#QPASSWD = 'password'
#QCERT_PASSWD = 'certpassword'

@contextlib.contextmanager
def pfx_to_pem(pfx_path, pfx_password):
    # Decrypts the .pfx file to be used with requests
    with tempfile.NamedTemporaryFile(suffix='.pem') as t_pem:
        f_pem = open(t_pem.name, 'wb')
        pfx = open(pfx_path, 'rb').read()
        p12 = OpenSSL.crypto.load_pkcs12(pfx, pfx_password)
        f_pem.write(OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, p12.get_privatekey()))
        f_pem.write(OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, p12.get_certificate()))
        ca = p12.get_ca_certificates()
        if ca is not None:
            for cert in ca:
                f_pem.write(OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, cert))
        f_pem.close()
        yield t_pem.name


# Extract Map Scan details
def mapscanreport(datafeed):
    datafeed = bytes(bytearray(datafeed, encoding='utf-8'))
    root = ET.fromstring(datafeed)

    for ip in root.iter('IP'):
        if not (ip.get('name')):  # findall(".//MAP/IP[not(@name)]/@value") not supported by ElementTree's XPath version
            print ip.get("value") + ";" + str(ip.get("os"))
            with open("mapscan.csv", "a") as f:
                f.write(str(ip.get("value")) + ";" + str(ip.get("os")) + "\n")

# Get a Map Scan Report
def getmapscan(url, username, password, certpassword):
    try: 
        with pfx_to_pem('certificate.pem', certpassword) as qcert:
            r = requests.get(url, auth=HTTPBasicAuth(username, password), headers={'X-Requested-With': 'testing'},cert=qcert)
        mapscanreport(r.text)
    except requests.ConnectionError as e:
        print "Connection Error\n"
        print str(e)
    except requests.Timeout as e:
        print "Timeout Error"
        print str(e)
    except requests.RequestException as e:
        print "General Error"
        print str(e)
        #sys.exit(1)
    except socket.error as e:
        print "Socket Error"
        print str(e)
        getmapscan(url, username, password, certpassword) # Workaround to get a map report if socket exception was raised, but it could lead to an infinite loop
        #sys.exit(1)


# Map Scan Reports list
def mapscanlist(datafeed, username, password, certpassword):
    datafeed = bytes(bytearray(datafeed, encoding='utf-8'))
    root = ET.fromstring(datafeed)

    for report in root.findall(
            ".//MAP_REPORT[@status='FINISHED']"):  # findall(".//MAP_REPORT[@status='FINISHED']/@ref") not supported by ElementTree's XPath version
        print report.get("ref")
        url = 'https://certs.qualys.eu/msp/map_report.php?ref=' + str(report.get("ref"))
        getmapscan(url, username, password, certpassword)
        # Avoid Qualys API Limits
        #time.sleep(1)

def main():
    if not QUSER or not QPASSWD or not QCERT_PASSWD:
        try:
            username = raw_input("Qualys Username: ")
            password = getpass.getpass("Qualys Password: ")
            certpassword = getpass.getpass("Qualys Certificate Password: ")
        except KeyboardInterrupt, e:
            sys.exit()
    else:
        username, password, certpassword = QUSER, QPASSWD, QCERT_PASSWD
    
    with pfx_to_pem('certificate.pem', certpassword) as qcert:
        r = requests.get('https://certs.qualys.eu/msp/map_report_list.php', auth=HTTPBasicAuth(username, password), headers={'X-Requested-With': 'testing'}, cert=qcert)
        # print r.text

        mapscanlist(r.text, username, password, certpassword)

if __name__ == '__main__':
    sys.exit(main())
