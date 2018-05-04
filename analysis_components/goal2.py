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
def main(apk, dvm, dx):
    result = [False, False, False, False]
    package = apk.get_package().replace(".", "/")
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
        # A lot of these come from libraries
        if re.match('https?://', string, re.IGNORECASE):
            urls.append(string)
    # Iterate through all classes
    for c in dvm.get_classes():
        # Skip classes not in this package
        if not (package in c.get_name()):
            continue
        for method in c.get_methods():
            for string in method.get_source().split("\n"):
                string = string.strip()
                #Q5    
                #check later if all managers and hostnames are being allowed
                if re.search(r'allow', string, re.IGNORECASE):
                    allow.append(string)
                if re.search(r'trust', string, re.IGNORECASE):
                    trust.append(string)
                #Q6
                #if a certificate is self signed, then generateCertificate() must be used to hardcode it
                #step1: read in certificate
                if re.search(r'generateCertificate', string, re.IGNORECASE):
                    flag1 += 1
                    # print("self signed certificate")
                #step2: create custom trustmanager
                #create keystore containing trusted CAs
                if re.search(r'keystore', string, re.IGNORECASE) and flag1>0:
                    flag2 += 1
                #create trust manager that trusts the CAs in our keystore
                if re.search(r'trustmanagerfactory', string, re.IGNORECASE) and flag2>0:
                    flag3 += 1
                #create sslcontext that uses our trustmanager
                if re.search(r'sslcontext', string, re.IGNORECASE) and flag3>0:
                    flag4 += 1
    #at the end of the app, if the 4th flag is down, then the self-signed certificate is correctly pinned 
    if flag1 > 0 and flag4 < 0:
        result[0] = True
        # print("self-signed certificate incorrectly pinned")
        
    # print(urls)
    for string in urls:
        if re.match('http://', string, re.IGNORECASE):
            count_http += 1
        if re.match('https://', string, re.IGNORECASE):
            count_https += 1
    if count_http>0 and count_https>0:
        result[1] = True
        # print('mix of http and https!')
            #if both are found, then the app is a mixture
    
    for string in allow:
        if re.search(r'all', string, re.IGNORECASE) and re.search(r'hostname', string, re.IGNORECASE):
            # print('allows all host name verifiers!')
            result[2] = True
            #if some variation of the string allowallhostnames is found
            
    for string in trust:
        if re.search(r'all', string, re.IGNORECASE) and re.search(r'manager', string, re.IGNORECASE):
            # print('allows all trust managers!')
            result[3] = True
            #if some variation of the string allowalltrustmanagers is found
    return result
       
        