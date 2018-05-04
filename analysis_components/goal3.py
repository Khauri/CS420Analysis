############################
# Interface Vulnerabilities (RQ 7, 8, 9): 
#
# An application may have vulnerable interfaces, or may not 
# sanitize data received from other applications.
############################
import re
import sys

NS_ANDROID_URI = 'http://schemas.android.com/apk/res/android'
NS_ANDROID = '{http://schemas.android.com/apk/res/android}'

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
    print("-- Analyzing Interface Vulnerabilities --")
    # Has Open Components, Receives Data, Uses Permission Protection
    result = [0, 0, 0]
    # Example: Get a list of the classes
    classes = dvm.get_classes()
    # A list of receivers/broadcatsts
    components = []
    l = []
    # 1. Get a list of open components
    # These are all the intents that can be called from another application
    perms = get_open_components(apk, components, l)
    if not len(components):
        return result
    else:
        result[0] = 1
    # RQ 7: Do these intents sanitize their input 
    # print(components)
    method_map = {
        "receiver" : "onReceive",
        "service" : "onStartCommand",
        "activity" : "onStart"
    }
    # Try to find the class that goes to the component
    for c in classes:
        for component in components:
            if not (component.get('class') in c.get_name()):
                continue
            for method in c.get_methods():
                src = method.get_source()
                # Search for strings such as 'get___Extra(s)'
                # Not foolproof but at least works a little
                if re.search(r'get.*?(?:Extras?|Data)', src):
                    # The app receives data through intent
                    # Therefor it may be vulnerable to hijacking
                    result[1] = 1
    # Check for password protection
    for component in components:
        if component.get('permission', False):
            result[2] = 1
    
    result.append(" ".join(perms) or None)
    return result

def get_open_components(apk, acc = {}, l =[]):
    # Get requested components with intent_filters
    intent_types = ['activity', 'service', 'receiver']
    # Get the 
    m = apk.get_declared_permissions_details()
    # 
    p = apk.get_details_permissions()

    manifest = apk.get_android_manifest_xml().find("application")
    perms = []
    for component in manifest:
        if not (component.tag in intent_types):
            continue
        name = component.get(NS_ANDROID+"name", None)
        # Check if component protected by a permission
        perm = component.get(NS_ANDROID+"permission", None)
        is_permission_protected = False
        # Check if component is exported
        exported = component.get(NS_ANDROID+"exported", "False")
        exported = re.match(r'true', exported, re.IGNORECASE) != None
        # Determine permission data
        if(perm):
            perms.append(perm)
            for permission in m.keys():
                if re.search(perm, permission, re.IGNORECASE):
                    pl = m[permission].get("protectionLevel")
                    if pl == '0x00000001' or pl == '0x00000002':
                        is_permission_protected = True
            for permission in p.keys():
                if re.search(perm, permission, re.IGNORECASE):
                    if 'dangerous' in p[permission]:
                        is_permission_protected = True
        # See if this elelment has an intent filter
        # This is the lazy way to do this
        intent = apk.get_intent_filters(component.tag, name)
        if (intent and not ('android.intent.action.MAIN' in intent.get('action', []))) or exported:
            acc.append({
                    "type" : component.tag,
                    "exported" : exported,
                    "permission" : is_permission_protected,
                    "class" : name.replace(".","/"),
                    "data" : intent
                }
            )
    return (perms)
            
    