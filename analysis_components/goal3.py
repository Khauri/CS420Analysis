############################
# Interface Vulnerabilities (RQ 7, 8, 9): 
#
# An application may have vulnerable interfaces, or may not 
# sanitize data received from other applications.
############################

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
    print("-- Analyzing Interface Vulnerabilities --")
    # Example: Get a list of the classes
    classes = dvm.get_classes()
    # print(classes)