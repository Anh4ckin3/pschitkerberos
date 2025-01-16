# Pschitkerberos

## Description

PschitKerberos is a tool for performing Kerberos authentication spraying attacks. This tool validates NT hashes against a Kerberos by attempting to retrieve a Ticket Granting Ticket (KRB_AS_REQ). It supports individual NT hashes or files containing multiple hashes.

PS:The tool assumes that the user provided as an argument is a valid domain user; if not, the program will terminate. To verify if a domain user is valid, [Kerbrute](https://github.com/ropnop/kerbrute) (Go) will do the job.

## Requirements

- Python 3.8 or later.

- impacket library for Kerberos authentication.

```
pip install -r requirements.txt
```

## Usage

```python
usage: python pschitkerberos.py [-h] [-username USERNAME] [-hash HASH] [-hashfile HASHFILE] -domain DOMAIN [-dc DC] [-verbose]

options:
  -username          Username for spraying NTLM hashes.
  -hash              Single NTLM hash to spray.
  -hashfile          File containing multiple NTLM hashes to spray.
  -domain            Target Kerberos domain (required).
  -dc                IP address of the Domain Controller (optional).
  -verbose           Enable verbose mode for detailed output.
```

## Examples
Spray a Single NTLM Hash :
```
> python pschitkerberos.py -username john.pork -hash 0123456789abcdef0123456789abcdef -domain example.com -dc 192.168.1.1 
```

Spray Multiple NTLM Hashes from a File
```
> python pschitkerberos.py -username john.pork -hashfile hashes.txt -domain example.com -dc 192.168.1.1
```
