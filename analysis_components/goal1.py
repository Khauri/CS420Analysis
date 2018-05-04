############################
# Permission misuse RQ: 1, 2, 3: 
# 
# An application's use of permissions may violate the user's privacy/security. 
# Understanding Android permissions, and what combinations of permissions may 
# be risky, is critical.
############################

import csv

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

def flagKirinConditions(permission):
    debugApp = 'android.permission.SET_DEBUG_APP' in permission
    phoneState = 'android.permission.READ_PHONE_STATE' in permission
    recordAudio = 'android.permission.RECORD_AUDIO' in permission
    internet = 'android.permission.INTERNET' in permission
    outgoingCall = 'android.permission.PROCESS_OUTGOING_CALL' in permission
    fineLocation = 'android.permission.ACCESS_FINE_LOCATION' in permission
    bootComplete = 'android.permission.RECEIVE_BOOT_COMPLETE' in permission
    coarseLocation = 'android.permission.ACCESS_COARSE_LOCATION' in permission
    receiveSMS = 'android.permission.RECEIVE_SMS' in permission
    sendSMS = 'android.permission.SEND_SMS' in permission
    writeSMS = 'android.permission.WRITE_SMS' in permission
    installShortcut = 'android.permission.INSTALL_SHORTCUT' in permission
    uninstallShortcut = 'android.permission.UNINSTALL_SHORTCUT' in permission
    
    #eight security rules follow
    if debugApp:
        return 1
    if phoneState and recordAudio and internet:
        return 2
    if outgoingCall and recordAudio and internet:
        return 3
    if fineLocation and internet and bootComplete:
        return 4
    if coarseLocation and internet and bootComplete:
        return 5
    if receiveSMS and writeSMS:
        return 6
    if sendSMS and writeSMS:
        return 7
    if installShortcut and uninstallShortcut:
        return 8 
    
    return 0

def writeCSV(apk, flag):
    package = apk.get_package()
    with open('goal1.csv', 'a') as f:
        writer = csv.writer(f, quoting=csv.QUOTE_MINIMAL)
        writer.writerow([package, flag])
        
def main(apk, dvm, dx):
    print("-- Analyzing Permission Missuse --")
    # Example: Get the app permissions

    permissions = apk.get_permissions()
    flag = flagKirinConditions(permissions)
    writeCSV(apk, flag)
   