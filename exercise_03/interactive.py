#%% Create Rizin instance
# 1. Extract the APK file
import zipfile
import os
import os.path

APK_PATH = "../samples/bladehawk.apk"
APK_NAME = os.path.splitext(os.path.basename(APK_PATH))[-2]

with zipfile.ZipFile(APK_PATH) as apk:
    os.makedirs(APK_NAME)
    apk.extractall(APK_NAME)

#%%
# 2. Open dexes with Rizin
import rzpipe

DEX_PATH = os.path.join(APK_NAME, "classes.dex")

rz = rzpipe.open(DEX_PATH)
rz.cmd("aa")

#%% Get all methods

# 1. Get all symbols
symbol_list = rz.cmdj("isj")

for symbol in symbol_list:
    # 2. Skip those symbols that are not functions or methods.
    
    # 3. Parse the address

    # 3. Parse the class name

    # 4. Parse the method name and descriptor

    # Print the method
    print(f"{address:0>5X} @ {class_name}->{method_name}{descriptor}")

#%% Find method by address
ADDRESS = 0x00005

# 1. Iterate all methods
symbol_list = rz.cmdj("isj")

for symbol in symbol_list:

    # 2. Check the address
    if ADDRESS == symbol['addr']:
        print(f"{address:0>5X} @ {class_name}->{method_name}{descriptor}")

#%% Cross-reference to the method
METHOD_ADDRESS = 0x0005

# 1. Seek to the method
rz.cmd(f"s {METHOD_ADDRESS}")

# 2. Get the information
xref_list = rz.cmdj(f"axtj")

for xref in xref_list:
    # 3. Skip those xrefs that are not related to method calls

    # 4. Get the address of a calling methods

    # 5. Find the method by the address
    
    # Print the calling method
    print(calling_method)

#%% Cross-references from the method
METHOD_ADDRESS = 0x0005

# 1. Seek to the method
rz.cmd(f"s {METHOD_ADDRESS}")

# 2. Get the information
xref_list = rz.cmdj(f"axtj")

for xref in xref_list:
    # 3. Skip those xrefs that are not related to method calls

    # 4. Get the address of a called methods

    # 5. Find the method by the address
    
    # Print the called method
    print(called_method)

#%% Get bytecodes of a method

# 1. Seek to the method

# 2. Iterate all the bytecodes
for bytecode in bytecode_list:
    # 3. Find the Smali representation

    # Print parsed bytecodes
    print(f"{smali_representation}")

#%% Get the inherence relationships of classes
INHERENCE_TREE = dict()

# 1. Get the information
graph_connections = rz.cmdj("icg").splitlines()

# 2. Iterate all elements
for graph_item in graph_connections:
    if graph_item.startswith("agn"):
        # 3. Parse a node in the graph

    elif graph_item.startswith("age"):
        # 4. Record the link between the parent and its children


#%% Parse the Android XML Format
