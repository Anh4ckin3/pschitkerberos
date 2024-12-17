# pschitkerberos

## Author

- [@Anh4ckin3](https://www.github.com/Anh4ckin3)

## Description

PschittKerberos is a tool for performing Kerberos authentication spraying attacks. This tool validates NTLM hashes against a Kerberos by attempting to retrieve a Ticket Granting Ticket (TGT). It supports individual NTLM hashes or files containing multiple hashes.

## Requirements

- Python 3.8 or later.

- impacket library for Kerberos authentication.

## Usage

```python
usage: python pschittkerberos.py [-h] [-username USERNAME] [-hash HASH] [-hashfile HASHFILE] -domain DOMAIN [-dc DC] [-verbose]

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
> python pschittkerberos.py -username john.doe -hash 0123456789abcdef0123456789abcdef -domain example.com -dc 192.168.1.1 
```

Spray Multiple NTLM Hashes from a File
```
> python pschittkerberos.py -username john.doe -hashfile hashes.txt -domain example.com -dc 192.168.1.1
```