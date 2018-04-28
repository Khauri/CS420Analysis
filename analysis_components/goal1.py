############################
# Permission misuse RQ: 1, 2, 3: 
# 
# An application's use of permissions may violate the user's privacy/security. 
# Understanding Android permissions, and what combinations of permissions may 
# be risky, is critical.
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
    print("Analyzing Permission Missuse")
    # Example: Get the app permissions
    permissions = apk.get_permissions()
    # print(permissions)