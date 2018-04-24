# import parsing scripts 
import analysis_components as components

# Analyze a specific application directory 
def analyze_app(directory):
    # Get manifest directory 
    manifest_loc = "c://path/to/manifest"
    components.manifest.analyze(manifest_loc)

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
    analyze_app("")

if __name__ == "__main__":
    # Get command line arguments
    # Analyze 
    analyze_directory("")