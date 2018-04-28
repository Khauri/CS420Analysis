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
    print("-- Analyzing SSL missuse --")
    # Example: Get a list of all the strings that start with "http(s)://"
    urls = []
    for string in dvm.get_strings():
        if re.match('https?://', string, re.IGNORECASE):
            urls.append(string)
    # print(urls)