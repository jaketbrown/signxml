#!/usr/bin/env python3
import io
import sys
import os
import atheris
with atheris.instrument_imports(include=['signxml']):
    from signxml import XMLSigner, XMLVerifier
    from signxml.exceptions import SignXMLException
    from lxml import etree
    from lxml.etree import XMLSyntaxError, DocumentInvalid


cert = """-----BEGIN CERTIFICATE-----
MIIEUTCCA7qgAwIBAgIBATANBgkqhkiG9w0BAQUFADCBrDELMAkGA1UEBhMCVVMx
CzAJBgNVBAgTAkNBMRUwEwYDVQQHEwxNb3VudGFpblZpZXcxETAPBgNVBAoTCERO
QW5leHVzMRMwEQYDVQQLEwpPcGVyYXRpb25zMRQwEgYDVQQDEwtETkFuZXh1cyBD
QTEZMBcGA1UEKRMQRE5BbmV4dXNQbGF0Zm9ybTEgMB4GCSqGSIb3DQEJARYRaW5m
b0BkbmFuZXh1cy5jb20wHhcNMTQwOTE1MDIwNjM3WhcNMjQwOTEyMDIwNjM3WjCB
rjELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNBMRUwEwYDVQQHEwxNb3VudGFpblZp
ZXcxETAPBgNVBAoTCEROQW5leHVzMRMwEQYDVQQLEwpPcGVyYXRpb25zMRYwFAYD
VQQDFA0qLmV4YW1wbGUuY29tMRkwFwYDVQQpExBETkFuZXh1c1BsYXRmb3JtMSAw
HgYJKoZIhvcNAQkBFhFpbmZvQGRuYW5leHVzLmNvbTCBnzANBgkqhkiG9w0BAQEF
AAOBjQAwgYkCgYEAvbCY1tXqnjH8gFfY8FDcBM4xXV43NOPp1eJ7Ke+z0PS5m8AO
w2i75LwtPx0Mn7itLpfB6x95kVkQbS1PXb/C/8FPdBqMLZGChzO+ZW7i5Nl6Ckdf
5QqumJcOObBqs0N1DQ/765gWZaUy2Yycl/xYlpY43R4m9zaDdirz+jGrsQkCAwEA
AaOCAX0wggF5MAkGA1UdEwQCMAAwEQYJYIZIAYb4QgEBBAQDAgZAMDQGCWCGSAGG
+EIBDQQnFiVFYXN5LVJTQSBHZW5lcmF0ZWQgU2VydmVyIENlcnRpZmljYXRlMB0G
A1UdDgQWBBRlDO8LQtZo/K38JQ2RLrh6uL43NTCB4QYDVR0jBIHZMIHWgBSvoZrl
dd3E70KF+jxbiTuu96w/lqGBsqSBrzCBrDELMAkGA1UEBhMCVVMxCzAJBgNVBAgT
AkNBMRUwEwYDVQQHEwxNb3VudGFpblZpZXcxETAPBgNVBAoTCEROQW5leHVzMRMw
EQYDVQQLEwpPcGVyYXRpb25zMRQwEgYDVQQDEwtETkFuZXh1cyBDQTEZMBcGA1UE
KRMQRE5BbmV4dXNQbGF0Zm9ybTEgMB4GCSqGSIb3DQEJARYRaW5mb0BkbmFuZXh1
cy5jb22CCQCJA4llz8RTkTATBgNVHSUEDDAKBggrBgEFBQcDATALBgNVHQ8EBAMC
BaAwDQYJKoZIhvcNAQEFBQADgYEAAqt0uP2c9VZY66apLY/vYYM2vCUWQqB0BYL0
PCI5OeEHzGOQF8DbD4fiqNHY2NTRO4M/n+gMve6vquOCBegs/fJIf5ZoWjLaUZRm
5PNOCO7zXt7VG3eGtq1MFfMiFD6bv7bAJCnnjtcxt6me+bxY0/QQkldxNE5pLam+
UiqB4gc=
-----END CERTIFICATE-----"""

key = """-----BEGIN PRIVATE KEY-----
MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAL2wmNbV6p4x/IBX
2PBQ3ATOMV1eNzTj6dXieynvs9D0uZvADsNou+S8LT8dDJ+4rS6XwesfeZFZEG0t
T12/wv/BT3QajC2RgoczvmVu4uTZegpHX+UKrpiXDjmwarNDdQ0P++uYFmWlMtmM
nJf8WJaWON0eJvc2g3Yq8/oxq7EJAgMBAAECgYA1Dp9BgCYWx46D645vcX6JDY97
OS4h6hnuzGF80mIucTU1XlwCxlm/2e6h96MfTc2K+cGw3WXohMv2bbUEWO3WlhAK
BZjwkF5Ipde5Bpv70vxGjgC6Y07xylHqySLrd5PKjVe1S3RAjTo4Syv84JM3cml7
cdta2Q7gTSz7jDZjHQJBAOv2Id62McYAireOShX1jbdrqlhI2c3uDvk/Q2W6g33/
XPv73E8DDJiXo5SAllZc1GP+8s2eMERI0zecwKnPSV8CQQDNzIG8NNzCbq+TaD/n
eNIkDUOQ+R/gr/y3NzLNmqhQV5ctCV2hEGMY/y6TdOxtUw5a0x4tagBhU+it29uu
LtaXAkAqm4U+K/QM5uglgQILuQ1gA4b87hq2PrhhdXT8F5PK2qO1tKLxeYF6xFb7
Z8S9z4FilRTO4DOjAOty7VE02INNAkEAol63AUIH5xOjTT8UJFGsIqugYnJb10+i
qP9RAu0B3RmueecIyzn9pcw3+DlpDDxaeAhXp+cZU7D7RKjRY1UrEwJAQkZ66CQc
rutqglc8uYV3R5i6V7SPp4ekAR3YGykOI9H5ujlHwA/PIifbF1+jkwvOxm+md7qh
uCnX6siFNDlUAg==
-----END PRIVATE KEY-----"""


def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)
    ran = 0#fdp.ConsumeIntInRange(0, 3)
    xml_str = fdp.ConsumeBytes(fdp.remaining_bytes())
    xml_str = b'<?xml version="1.0"?><data>' + xml_str + b'</data>'
    try:
        tree = etree.parse(io.BytesIO(xml_str))
        data = tree.getroot()
        if ran == 0:
            signed = XMLSigner().sign(data, key=key, cert=cert)
            XMLVerifier().validate_schema(signed)
        #elif ran == 1:
            signed1 = XMLSigner().sign(data, key=key, cert=cert, always_add_key_value=True)
            XMLVerifier().get_root(signed1)
        #elif ran == 2:
            signed2 = XMLSigner().sign(data, key=key, cert=cert, always_add_key_value=False)
            XMLVerifier().schemas()
            XMLVerifier().get_root(signed2)
        #else:
            signed3 = XMLSigner().sign(data, key=key, cert=cert)
            signed_data = etree.tostring(signed3)
            XMLVerifier().verify(signed_data, ca_pem_file=os.path.dirname(os.path.abspath(__file__)) + '/example-ca.pem')

            signed1 = XMLSigner().sign(data, key=key, cert=cert, always_add_key_value=True)
            XMLVerifier().get_root(signed1)
    except (XMLSyntaxError, SignXMLException, DocumentInvalid):
        return
    except Exception:
        raise


def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


# Main program
if __name__ == "__main__":
    main()
