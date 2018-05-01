# import parsing scripts 
import os 
import re
import sys
import argparse

from androguard.core.bytecodes.apk import APK
from androguard.core.androconf import show_logging
from androguard.core.analysis.analysis import Analysis
from androguard.core.bytecodes.dvm import DalvikVMFormat
from androguard.decompiler.decompiler import DecompilerJADX

import analysis_components as components

# Analyze a specific application directory 
def analyze_app(apk_filename):
    print("APK: %s" % apk_filename)
    # Load the APK
    apk = APK(apk_filename)
    # Create DalvikVMFormat Object
    if apk.is_multidex():
        d = DalvikVMFormat(apk.get_all_dex())
    else:
        d = DalvikVMFormat(apk)
    # components.goal1.main(apk, d)
    # components.goal2.main(apk, d)
    components.goal3.main(apk, d)
    print("")

# 1. Decompose the apk 
# 2. Analyze the decomposed application
# 3. Export results 
def analyze_directory(directory, num):
    ''' 
    Analyze an entire directory of decompiled or non-decompiled
    andorid applications
    '''
    # iterate through directory searching for apks 
    # decompile app if not already decompiled 
    # analyze the application
    path = os.path.abspath(directory)
    for p, d, f in os.walk(path):
        for filename in f:
            absp = os.path.abspath(os.path.join(p, filename))
            if absp.endswith('.apk'):
                analyze_app(absp)
                num -= 1
                if num <= 0:
                    return

if __name__ == "__main__":
    # decompiler = DecompilerJADX(d, dx, jadx="/home/vagrant/jadx/build/jadx/bin/jadx")
    # Get and parse command line arguments
    descr = "This program analyzes apk's for vulnerabilities"
    parser = argparse.ArgumentParser(description = descr)
    parser.add_argument("-i", "--input",      help="The input directory")
    parser.add_argument("-n", "--number", type=int, help="The maximum number to analyze")
    # parser.add_argument("-p", "--printstdio", help="Print to stdio instead of output file", action="store_true", )
    args = parser.parse_args()
    if args.input:
        print("Analyzing from directory %s" % args.input)
    analyze_directory(args.input or os.path.join(".","apps"), args.number or float('inf'))