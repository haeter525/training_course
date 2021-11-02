#%% Create Rizin instance
# 1. Extract the APK contents
import zipfile
import os
import os.path

APK_PATH = "../samples/bladehawk.apk"
APK_NAME = os.path.splitext(os.path.basename(APK_PATH))[-2]

with zipfile.ZipFile(APK_PATH) as apk:
    os.makedirs(APK_NAME)
    apk.extractall(APK_NAME)

# 2. Open dexes with Rizin
import rzpipe

DEX_PATH = os.path.join(APK_NAME, "classes.dex")

rz = rzpipe.open(DEX_PATH)
rz.cmd("aaa")

#%% Get all methods
import rzpipe

# 1. Get all symbols
symbol_list = rz.cmdj("isj")

for symbol in symbol_list:
    # 2. Skip those symbols that are not functions or methods.
    if symbol.get("type") not in ['FUNC', 'METH']:
        continue

    # 3. Parse the address
    address = symbol['vaddr']

    # 3. Parse the class name
    class_name = symbol['realname'][:symbol.index('.method.')] + ';'

    # 4. Parse the method name and descriptor
    method_signature = symbol['realname'][symbol.index('.method.')+7:]
    method_name = method_signature[:method_signature.index('(')]
    descriptor = method_signature[method_signature.index('('):]

    # Print the method
    print(f"{address:0>5X} @ {class_name}->{method_name}{descriptor}")

#%% Find method by address
import rzpipe

ADDRESS = 0x00005

# 1. Iterate all methods
symbol_list = rz.cmdj("isj")

for symbol in symbol_list:

    # 2. Check the address
    if ADDRESS == symbol['addr']:
        print(f"{address:0>5X} @ {class_name}->{method_name}{descriptor}")

#%% Cross-reference to the method
import rzpipe

METHOD_ADDRESS = 0x0005

# 1. Seek to the method
rz.cmd(f"s {METHOD_ADDRESS}")

# 2. Get the information
xref_list = rz.cmdj(f"axtj")

for xref in xref_list:
    # 3. Skip those xrefs that are not related to method calls
    if xref['type'] != 'CALL':
        continue

    # 4. Get the address of a calling methods
    address = xref.get('from', None)

    # 5. Find the method by the address
    calling_method = get_method_by_address(address)
    
    # Print the calling method
    print(calling_method)

#%% Cross-references from the method
import rzpipe

METHOD_ADDRESS = 0x0005

# 1. Seek to the method
rz.cmd(f"s {METHOD_ADDRESS}")

# 2. Get the information
xref_list = rz.cmdj(f"axtj")

for xref in xref_list:
    # 3. Skip those xrefs that are not related to method calls
    if xref['type'] != 'CALL':
        continue

    # 4. Get the address of a called methods
    address = xref.get('from', None)

    # 5. Find the method by the address
    called_method = get_method_by_address(address)
    
    # Print the called method
    print(called_method)

#%% Get bytecodes of a method
import rzpipe
METHOD = "0x0005"

# 0. Parse the method address
address = 0x0005

# 1. Seek to the method
rz.cmd(f"s {address}")

# 2. Get the method information
method_information = rz.cmdj(f"pdfj")

# 3. Get the bytecode list
bytecode_list = method_information['ops']

# 2. Iterate all the bytecodes
for bytecode in bytecode_list:
    # 3. Find the Smali representation
    smali_representation = bytecode['disasm']

    # Print parsed bytecodes
    print(f"{smali_representation}")

#%% Get the inherence relationships of classes
import rzpipe

INHERENCE_TREE = dict()

# 1. Get the information
graph_connections = rz.cmdj("icg").splitlines()

# 2. Iterate all elements
for graph_item in graph_connections:
    if graph_item.startswith("agn"):
        # 3. Parse a node in the graph
        parent = graph_item.split()[1]
        if not parent.endswith(';'): parent = parent + ';'
        INHERENCE_TREE[parent] = []

    elif graph_item.startswith("age"):
        # 4. Record the link between the parent and its children
        children = graph_item.split()[2:]
        for child in children:
            if not child.endswith(';'): child = child + ';'
        INHERENCE_TREE[parent].append(children)

    # Print the subclass of a specific class
    print(INHERENCE_TREE["Ljava/util/Map;"])
#%% Parse the Android XML Format
# TODO - Update the PPT