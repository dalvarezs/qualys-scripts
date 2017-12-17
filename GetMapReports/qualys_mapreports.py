#!/usr/bin/env python

"""
17/12/2017
"""

import contextlib
import OpenSSL.crypto
import requests
from requests.auth import HTTPBasicAuth
import tempfile
import xml.etree.ElementTree as ET

__author__ = 'David Alvarez @dalvarez_s'
__version__ = '0.1'
__doc__ = 'Connects to Qualys API. Get list of Map reports finished and extract hosts without DNSname ' \
          'UseCase: Useful for identifying live hosts without DNSname'


QUSER = 'user'
QPASSWD = 'password'
QCERT_PASSWD = 'certpassword'


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


# Map Scan details
def mapscanreport(datafeed):
    datafeed = bytes(bytearray(datafeed, encoding='utf-8'))
    root = ET.fromstring(datafeed)

    for ip in root.iter('IP'):
        if not (ip.get('name')):  # findall(".//MAP/IP[not(@name)]/@value") not supported by ElementTree's XPath version
            print ip.get("value") + "," + str(ip.get("os"))


# Map Scan Reports list
def mapscanlist(datafeed):
    datafeed = bytes(bytearray(datafeed, encoding='utf-8'))
    root = ET.fromstring(datafeed)

    for report in root.findall(
            ".//MAP_REPORT[@status='FINISHED']"):  # findall(".//MAP_REPORT[@status='FINISHED']/@ref") not supported by ElementTree's XPath version
        print report.get("ref")
        url = 'https://certs.qualys.eu/msp/map_report.php?ref=' + str(report.get("ref"))
        r = requests.get(url, auth=HTTPBasicAuth(QUSER, QPASSWD), headers={'X-Requested-With': 'testing'},
                         cert=cert)
        mapscanreport(r.text)


with pfx_to_pem('foo.pem', QCERT_PASSWD) as cert:
    r = requests.get('https://certs.qualys.eu/msp/map_report_list.php', auth=HTTPBasicAuth(QUSER, QPASSWD),
                     headers={'X-Requested-With': 'testing'}, cert=cert)
    # print r.text

    mapscanlist(r.text)
