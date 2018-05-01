# -*- coding: utf-8 -*-
"""
Created on Sun Apr 29 18:43:14 2018

@author: Jill
"""

############################
# SSL API misuse (RQ 4, 5, 6): 
#
# An application's network communication may be vulnerable (i.e., due to not 
# using SSL, or using it incorrectly).
############################
import re

'''
The main starting point for this analysis. The objects needed to analyze
an apk are passed in as parameters to this function.
@param apk -    AndroGuard APK instance
                Used for getting information about the app. i.e. icon, intents, permissions, resources, etc... 
                See: https://github.com/androguard/androguard/blob/master/androguard/core/bytecodes/apk.py#L55
@param dvm - Androguard DalvikVMFormat instance
                Used for analyzing "decompiled" code
                see: https://github.com/androguard/androguard/blob/master/androguard/core/bytecodes/dvm.py#L7471
'''
def main(apk, dvm):
    count_http = 0
    count_https = 0
    
    flag1 = 0
    flag2 = 0
    flag3 = 0
    flag4 = 0
    print("-- Analyzing SSL missuse --")
    
    # Example: Get a list of all the strings that start with "http(s)://"
    urls = []
    allow = [] #all strings that contain 'allow'
    trust = [] #all strings that contain 'trust'
    
    for string in dvm.get_strings():
        #Q4
        #check later if there is mixed use
        if re.match('https?://', string, re.IGNORECASE):
            urls.append(string)
        #Q5    
        #check later if all managers and hostnames are being allowed
        if re.match('allow', string, re.IGNORECASE):
            allow.append(string)
        if re.match('trust', string, re.IGNORECASE):
            trust.append(string)
        #Q6
        #if a certificate is self signed, then generateCertificate() must be used to hardcode it
        #step1: read in certificate
        if re.match('generateCertificate', string, re.IGNORECASE):
            flag1 += 1
            print("self signed certificate")
        #step2: create custom trustmanager
        #create keystore containing trusted CAs
        if re.match('keystore', string, re.IGNORECASE) and flag1>0:
            flag2 += 1
        #create trust manager that trusts the CAs in our keystore
        if re.match('trustmanagerfactory', string, re.IGNORECASE) and flag2>0:
            flag3 += 1
        #create sslcontext that uses our trustmanager
        if re.match('sslcontext', string, re.IGNORECASE) and flag3>0:
            flag4 += 1
    #at the end of the app, if the 4th flag is down, then the self-signed certificate is correctly pinned 
    if flag1>0 and flag4<0:
        print("self-signed certificate incorrectly pinned")
        
    # print(urls)
    for string in urls:
        if re.match('http://', string, re.IGNORECASE):
            count_http += 1
        if re.match('https://', string, re.IGNORECASE):
            count_https += 1
        if count_http>0 and count_https>0:
            print('mix of http and https!')
            #if both are found, then the app is a mixture
    
    for string in allow:
        if re.match('all', string, re.IGNORECASE) and re.match('hostname', string, re.IGNORECASE):
            print('allows all host name verifiers!')
            #if some variation of the string allowallhostnames is found
            
    for string in trust:
        if re.match('all', string, re.IGNORECASE) and re.match('manager', string, re.IGNORECASE):
            print('allows all trust managers!')
            #if some variation of the string allowalltrustmanagers is found
       
        