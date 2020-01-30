#!/usr/bin/env python3
#
# a script to enumerat all subdomains of a domain and  check to see if the server is still vulnerable to CVE-2019-19781
# Written by: Aussan Saad-Ali, @aussan_m
# Company: SiraSec
#
import argparse
import os
import pathlib
import re
import subprocess
import sys
import threading
from datetime import date, datetime, time

import requests
import urllib3
from bs4 import BeautifulSoup
from netaddr import IPNetwork


def get_asn_number():
    #run amass to get the ASN numbers of an organization
    print("Retriving ASN nmbers of the organizaiotn "+orgname)
    command = 'amass intel -org '+orgname
    asnList = subprocess.Popen([command], shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stderr_read = asnList.stderr.read().decode('utf-8')
    asnList = asnList.stdout.read().decode('utf-8').splitlines()
    
    with open(asnResults, 'w') as f:
        for asn in asnList:
            asnNumber = (asn.split(","))[0]
            f.write("%s\n" % asnNumber)
            asn_convert = get_cidr(asnNumber)
    
            with open(cidrResults, 'a') as f2:
                for cidr in asn_convert:
                    print("cidrr is {}".format(cidr))
                    f2.write("%s\n" % cidr)
            
            
    #print("CIDR found: ==> " + str(asn_convert))
    
        
    #print("asn found: ==> " + str(asnList))
    f.close()
    f2.close()
    
    return
        
def get_cidr(asn):
    # use ASN listings to enumerate whois information for scanning.

    command = 'whois -h whois.radb.net -- \'-i origin %s\' | grep -Eo "([0-9.]+){4}/[0-9]+" | head' % (asn)
    asn_convert = subprocess.Popen([command], shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stderr_read = asn_convert.stderr.read().decode('utf-8')
    asn_convert = asn_convert.stdout.read().decode('utf-8').splitlines()

    # if we don't have whois installed
    if "whois: not found" in stderr_read:
        print("[-] In order for ASN looks to work you must have whois installed. Type apt-get install whois as an example on Debian/Ubuntu.")
        sys.exit()
    # iterate through cidr ranges and append them to list to be scanned 
    
    #print("CIDR found: ==> " + str(asn_convert))
    
    return(asn_convert)

def get_subdomains():
    
    print("getting subdomains for",domain)
    assetcmd = 'assetfinder -subs-only '+domain
    print("running",assetcmd)
    subdmnList = subprocess.Popen([assetcmd], shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stderr_read = subdmnList.stderr.read().decode('utf-8')
    subdmnList = subdmnList.stdout.read().decode('utf-8').splitlines()
    
    print("sorting the following subdomains, ", subdmnList)
    amasscmd= 'amass enum --passive -d '+domain
    print("running",amasscmd)
    subdmnList = subprocess.Popen([amasscmd], shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stderr_read = subdmnList.stderr.read().decode('utf-8')
    subdmnList = subdmnList.stdout.read().decode('utf-8').splitlines()
    
    subdmnList = sorted(set(subdmnList))
    
    print("Writting output file with, ", subdmnList)
    with open(subdmnResults, 'w') as f:
        for subdmn in subdmnList:
            print("found",subdmn)
            f.write("%s\n" % subdmn)
   # with open(asnResults, 'r') as file_in:
   #     for asn in file_in:
   #         print("Processing ASN # {}".format(asn))
   #         command = 'amass intel -asn '+asn
   #         subdomainList = subprocess.Popen([command], shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
   #         stderr_read = subdomainList.stderr.read().decode('utf-8')
   #         subdomainList = subdomainList.stdout.read().decode('utf-8').splitlines()
   #         with open(subdmnResults, 'a') as f:
   #             for subdmn in subdomainList:
   #                 print("subdomain is {}".format(subdmn))
   #                 f.write("%s\n" % subdmn)
                

    
    
    f.close()
 
    return      
            
     

def main(org):
    global domain, orgname, resultsDir, companyDir, asnResults, cidrResults, subdmnResults
    domain = sys.argv[1]
    orgname = domain.split(".")[0]
    resultsDir = str(os.getcwd())+"/results"
    companyDir = resultsDir+"/"+orgname
    asnResults = companyDir+"/"+orgname+"_asns.txt"
    cidrResults = companyDir+"/"+orgname+"_cdr.txt"
    subdmnResults = companyDir+"/"+orgname+"_subdmn.txt"
    
    if not os.path.exists(resultsDir):
        os.makedirs(resultsDir)
    
    if not os.path.exists(companyDir):
        os.makedirs(companyDir)
    
    if os.path.exists(asnResults):
        os.remove(asnResults)
    if os.path.exists(cidrResults):
        os.remove(cidrResults)
    if os.path.exists(subdmnResults):
        os.remove(subdmnResults)
    
        
    print("starting with the retrival of the ASN numbers for "+orgname)
    get_asn_number()
    
    get_subdomains()

    print("Program completed")
    
if __name__ == "__main__":
    command = os.path.basename(__file__)
    try:
        arg1 = sys.argv[1]
    except IndexError:
        print("you need to enter the domain name as argument")
        print("Usage: ",command," yahoo")
        sys.exit(1)

    main(arg1)
