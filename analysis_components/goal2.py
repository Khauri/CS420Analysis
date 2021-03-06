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
from androguard.misc import AnalyzeAPK
from androguard.core.bytecodes.apk import APK
from androguard.misc import clean_file_name

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
                if re.search('allow', string, re.IGNORECASE):
                    allow.append(string)
                if re.search('trust', string, re.IGNORECASE):
                    trust.append(string)

                #Q6
                #if a certificate is self signed, then generateCertificate() must be used to hardcode it
                #step1: read in certificate
                if re.search('certificate', string, re.IGNORECASE):
                    flag1 +=1
                if flag1>0 and re.search('okhttp', string, re.IGNORECASE):
                    result[0]=True
                if flag1>0 and re.search('validatepin', string, re.IGNORECASE):
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
        if re.search('all', string, re.IGNORECASE) and re.search('hostname', string, re.IGNORECASE):
            # print('allows all host name verifiers!')
            result[2] = True
            #if some variation of the string allowallhostnames is found

    for string in trust:
        if re.search('all', string, re.IGNORECASE) and re.search('manager', string, re.IGNORECASE):
            # print('allows all trust managers!')
            result[3] = True
            #if some variation of the string allowalltrustmanagers is found
    return result