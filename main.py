# import parsing scripts 
import os 
import re
import sys
import csv
import argparse
from timeit import default_timer as timer

from androguard.misc import AnalyzeAPK
from androguard.core.bytecodes.apk import APK
from androguard.core.bytecodes.dvm import DalvikVMFormat

import analysis_components as components

# Analyze a specific application directory 
def analyze_app(apk_filename):
    print("APK: %s" % apk_filename)
    apk, d, dx = AnalyzeAPK(apk_filename)
    app_name = apk.get_app_name()
    with open('goal1.csv', 'a') as csvfile:
        writer = csv.writer(csvfile, quoting=csv.QUOTE_MINIMAL)
        result = components.goal1.main(apk, d[0], dx)
        result.insert(0, app_name)
        writer.writerow(result)

    with open('goal2.csv', 'a') as csvfile:
        writer = csv.writer(csvfile, quoting=csv.QUOTE_MINIMAL)
        result = components.goal2.main(apk, d[0], dx)
        result.insert(0, app_name)
        writer.writerow(result)

    with open('goal3.csv', 'a') as csvfile:
        writer = csv.writer(csvfile, quoting=csv.QUOTE_MINIMAL)
        result = components.goal3.main(apk, d[0], dx)
        result.insert(0, app_name)
        writer.writerow(result)
    print("")

# 1. Decompose the apk 
# 2. Analyze the decomposed application
# 3. Export results 
def analyze_directory(directory, num):
    ''' 
    Analyze an entire directory of decompiled or non-decompiled
    andorid applications
    '''
    Create the CSV files (erases existing code)
    with open('goal1.csv', 'wb') as csvfile:
        writer = csv.writer(csvfile, quoting=csv.QUOTE_MINIMAL)
        writer.writerow(['App']) 

    with open('goal2.csv', 'w') as csvfile:
        writer = csv.writer(csvfile, quoting=csv.QUOTE_MINIMAL)
        writer.writerow(['App', 'Incorrectly Pinned SSC', 
            'SSL Mixing', 'Allow All Hostnames', 'Allow All Trust Manager'])

    with open('goal3.csv', 'w') as csvfile:
        writer = csv.writer(csvfile, quoting=csv.QUOTE_MINIMAL)
        writer.writerow(['App', 'Open Components', 'Receives Data', 'Permission Checking', "Component Permissions" ]) # TODO

    # iterate through directory searching for apks 
    # analyze the application
    with open('log.txt', 'w') as logfile:
        failures = 0
        path = os.path.abspath(directory)
        for p, d, f in os.walk(path):
            for filename in f:
                absp = os.path.abspath(os.path.join(p, filename))
                if absp.endswith('.apk'):
                    if num <= 0:
                        return
                    try:
                        analyze_app(absp)
                        num -= 1
                    except:
                        logfile.write(absp + "\n")
                        failures += 1
        logfile.write("Total Failues: " + str(failures))

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
    start = timer()
    analyze_directory(args.input or os.path.join(".","apps"), args.number or float('inf'))
    print(timer() - start)