############################
# Interface Vulnerabilities (RQ 7, 8, 9): 
#
# An application may have vulnerable interfaces, or may not 
# sanitize data received from other applications.
############################
import sys
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
    # A list of receivers/broadcatsts
    components = {}
    l = []
    # 1. Get a list of open components
    # These are all the intents that can be called implicitly
    get_open_components(apk, components, l)
    # RQ 7: Do these intents sanitize their input 
    print(components)
    for c in classes:
        pass
        # for l2 in l:
        #     if l2 in c.get_name():
        #         print(c.get_name())
        # for method in c.get_methods():
        #     print(method)

def sanitizes_input():
    pass

def get_open_components(apk, acc = {}, l =[]):
    # Get requested components with intent_filters
    intent_types = ['activity', 'service', 'receiver', 'provider']
    for t in intent_types:
        # Get requested components with "export" flag
        exported = [n for n in apk.get_elements(t, 'exported') if n.endswith('true')]
        if exported:
            if not acc.get(t):
                acc[t] = []
            for export in exported:
                acc[t].append({
                        "class" : "/".join(export.split(".")[:-1]),
                        "data" : {"category" : ["EXPORTED"]}
                    }
                )
        for item in apk.get_elements(t, "name"):
            intent = apk.get_intent_filters(t, item)
            if intent and not ('android.intent.action.MAIN' in intent.get('action', [])):
                if not acc.get(t):
                    acc[t] = []
                acc[t].append({
                        "class" : item.replace(".","/"),
                        "data" : intent
                    }
                )
    return acc
            
    