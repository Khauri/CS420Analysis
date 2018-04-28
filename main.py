# import parsing scripts 
import os 
import re
import sys
import argparse
import androguard

import analysis_components as components

# Analyze a specific application directory 
def analyze_app(directory):
    # Get manifest directory 
    print(directory)
    manifest_loc = "c://path/to/manifest"
    components.goal1.main()
    components.goal2.main()
    components.goal3.main()

# 1. Decompose the apk 
# 2. Analyze the decomposed application
# 3. Export results 
def analyze_directory(directory):
    ''' 
    Analyze an entire directory of decompiled or non-decompiled
    andorid applications
    '''
    # iterate through directory searching for apks 
    # decompile app if not already decompiled 
    # analyze the application
    path = os.path.abspath(directory)
    print(path)
    analyze_app("")

if __name__ == "__main__":
    # Get and parse command line arguments
    descr = "This program analyzes apk's for vulnerabilities"
    parser = argparse.ArgumentParser(description = descr)
    parser.add_argument("-i", "--input",      help="The input directory")
    # parser.add_argument("-o", "--output",     help="The output filename")
    # parser.add_argument("-p", "--printstdio", help="Print to stdio instead of output file", action="store_true", )
    args = parser.parse_args()
    if args.input:
        print("Analyzing from directory %s" % args.input)
    analyze_directory(args.input or os.path.join(".","apps"))