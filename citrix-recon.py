#!/usr/bin/env python3
#
# a script to enumerat all subdomains of a domain and  check to see if the server is still vulnerable to CVE-2019-19781
# Written by: Aussan Saad-Ali, @aussan_m
# Company: SiraSec
#
import requests
import urllib3
import argparse
import threading
import subprocess
import re
import sys
import pathlib
import os
from datetime import date
from datetime import time
from datetime import datetime
from bs4 import BeautifulSoup
from netaddr import IPNetwork


def get_asn_number():
    #run amass to get the ASN numbers of an organization
    print("Retriving ASN nmbers of the organizaiotn "+orgname)
    command = 'amass intel -org '+orgname
    asnList = subprocess.Popen([command], shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stderr_read = asnList.stderr.read().decode('utf-8')
    asnList = asnList.stdout.read().decode('utf-8').splitlines()
    asnResults = companyDir+"/"+orgname+"_asns.txt"
    with open(asnResults, 'w') as f:
        for asn in asnList:
            f.write("%s\n" % asn)
            asnNumber = (asn.split(","))[0]
            print("Processing ASN "+asnNumber)
            asn_convert = get_cidr(asnNumber)
                
        
def get_cidr(asn):
    # use ASN listings to enumerate whois information for scanning.

    command = 'whois -h whois.radb.net -- \'-i origin %s\' | grep -Eo "([0-9.]+){4}/[0-9]+" | head' % (asn)
    asn_convert = subprocess.Popen([command], shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stderr_read = asn_convert.stderr.read().decode('utf-8')
    asn_convert = asn_convert.stdout.read().decode('utf-8').splitlines()
    cidrResults = companyDir+"/"+orgname+"_cidr.txt"


    # if we don't have whois installed
    if "whois: not found" in stderr_read:
        print("[-] In order for ASN looks to work you must have whois installed. Type apt-get install whois as an example on Debian/Ubuntu.")
        sys.exit()
    # iterate through cidr ranges and append them to list to be scanned 
    
    print("CIDR found: ==> " + str(asn_convert))
    with open(cidrResults, 'w') as f:
        for cidr in asn_convert:
            print("CIDR is {}".format(cidr))
            f.write("%s\n" % cidr)
    
    return(asn_convert)

def main(org):
    global orgname, resultsDir, companyDir
    
    orgname = sys.argv[1]
    resultsDir = str(os.getcwd())+"/results"
    companyDir = resultsDir+"/"+orgname
    
    if not os.path.exists(resultsDir):
        os.makedirs(resultsDir)
    
    if not os.path.exists(companyDir):
        os.makedirs(companyDir)
        
    print("starting with the retrival of the ASN numbers for "+orgname)
    get_asn_number()
    
    
if __name__ == "__main__":

    main(sys.argv[1])