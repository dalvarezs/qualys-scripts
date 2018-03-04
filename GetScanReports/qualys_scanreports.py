#!/usr/bin/env python

"""
04/03/2018
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
import socket #socket exception

__author__ = 'David Alvarez @dalvarez_s'
__version__ = '0.1'
__doc__ = 'Connects to Qualys API. Get list of Scan reports finished and download the reports' \
          'UseCase: Useful for downloading reports in bulk'

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


# Get a Map Scan Report
def getscan(url, title, outputformat, username, password, certpassword):
    try: 
        with pfx_to_pem('certificate.p12', certpassword) as qcert:
            r = requests.get(url, auth=HTTPBasicAuth(username, password), headers={'X-Requested-With': 'testing'},cert=qcert)
            with open(title+"."+outputformat.lower(), "a") as f:
                f.write(r.content)
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
def scanlist(datafeed, username, password, certpassword):
    datafeed = bytes(bytearray(datafeed, encoding='utf-8'))
    root = ET.fromstring(datafeed)

    for report in root.findall(
            ".//REPORT"):  # findall(".//MAP_REPORT[@status='FINISHED']/@ref") not supported by ElementTree's XPath version
        #print report.find('ID').text
        title = report.find('TITLE').text
        outputformat = report.find('OUTPUT_FORMAT').text
        url = 'https://certs.qualys.eu/api/2.0/fo/report?action=fetch&id=' + str(report.find('ID').text)
        print "Downloading report "+report.find('TITLE').text+"."+report.find('OUTPUT_FORMAT').text
        getscan(url, title, outputformat, username, password, certpassword)
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
    
    with pfx_to_pem('certificate.p12', certpassword) as qcert:
        r = requests.get('https://certs.qualys.eu/api/2.0/fo/report?action=list&state=Finished', auth=HTTPBasicAuth(username, password), headers={'X-Requested-With': 'testing'}, cert=qcert)
        #print r.text

        scanlist(r.text, username, password, certpassword)

if __name__ == '__main__':
    sys.exit(main())
