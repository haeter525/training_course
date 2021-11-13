import os
import os.path
import zipfile
from functools import cached_property
from typing import *

import rzpipe
from exercise_03.core.methodobject import MethodObject


class RizinImp:
    def __init__(self, apk_filepath):
        apk_name = os.path.splitext(os.path.basename(apk_filepath))[-2]

        # 1. Extract the APK contents
        with zipfile.ZipFile(apk_filepath) as apk:
            os.makedirs(apk_name)
            apk.extractall(apk_name)

            # Path to AndroidManifest.xml
            self._manifest = os.path.join(self._tmp_dir, "AndroidManifest.xml")

            # Open all dex with Rizin
            dex_path_list = [
                os.path.join(self._tmp_dir, filename)
                for filename in apk.namelist()
                if filename.startswith("classes") and filename.endswith(".dex")
            ]

        self._rz = self._create_rizin(dex_path_list)

    @staticmethod
    def _create_rizin(dex_list):
        # Open all dexes
        rz = rzpipe.open(dex_list[0])
        for dex_path in dex_list[1:]:
            rz.cmd(f"o {dex_path}")

        # Analyze cross-references
        rz.cmd("aaa")

    @cached_property
    def permissions(self) -> List[str]:
        """
        Return all permissions from given APK.

        :return: a list of all permissions
        """
        # AXML Reader
        reader = AxmlReader(self._manifest)
        permission_list = set()

        # Iterate through all XML nodes
        for node in reader:
            # Test if a node defines an APP permission
            label = node.get("Name")
            if label and reader.get_string(label) == "usespermission":
                # Get the content of the node
                attrs = reader.get_attributes(node)
                if attrs:
                    permission = reader.get_string(attrs[0]["Value"])
                    # Collect the permission
                    permission_list.add(permission)

        return permission_list

    @property
    def all_methods(self) -> Set[MethodObject]:
        """
        Return all methods including Android native API and custom methods from given APK.

        :return: a set of all method MethodObject
        """
        # 1. Send the command "isj"
        symbol_list = self._rz.cmdj('isj')

        for symbol in symbol_list:
            # 2. Skip if the symbol is not a function or method
            if symbol.get('type') not in ['FUNC', 'METH']:
                continue

            # 3. Parse class name, method name, and descriptor
            # e.g. La/b/c/d/BuildConfig.method.<init>()V

        pass

    def find_method(
        self,
        class_name: Optional[str] = ".*",
        method_name: Optional[str] = ".*",
        descriptor: Optional[str] = ".*",
    ) -> MethodObject:
        """
        Find method from given class_name, method_name and the descriptor.
        default is find all method.

        :param class_name: the class name of the Android API
        :param method_name: the method name of the Android API
        :param descriptor: the descriptor of the Android API
        :return: a generator of MethodObject
        """
        # 1. Iterate through all methods

        # 2. Compare with the class names, method names, and descriptors

        pass

    def _get_method_by_address(self, address: int) -> MethodObject:
        # 1. Iterate through all methods

        # 2. Compare with the addresses

        pass

    def upperfunc(self, method_object: MethodObject) -> Set[MethodObject]:
        """
        Return the xref from method from given MethodObject instance.

        :param method_object: the MethodObject instance
        :return: a set of all xref from functions
        """
        # 1. Move the cursor to the target method

        # 2. Send the command "axtj"

        # 3. Skip those xrefs that are not method calls

        # 4. Get the address of a calling method

        # 5. Find the corresponding method object by the address

        # 6. Collect the method object

        pass

    def lowerfunc(self, method_object: MethodObject) -> Set[MethodObject]:
        """
        Return the xref from method from given MethodObject instance.

        :param method_object: the MethodObject instance
        :return: a set of all xref from functions
        """
        # 1. Move the cursor the the target method

        # 2. Send the command "axff"

        # 3. Skip those xrefs that are not method calls

        # 4. Get the address of a calling method

        # 5. Find the corresponding method object by the address

        # 6. Collect the method object

        pass

    def get_method_bytecode(self, method_object: MethodObject) -> Set[str]:
        """
        Return the corresponding bytecode according to the
        given class name and method name.

        :param method_object: the MethodObject instance
        :return: a generator of all bytecode instructions
        """
        # 0. Parse the method address

        # 1. Move the cursor to the address

        # 2. Send the command "pdfj"

        # 3. Get the bytecode list

        # 4. Iterate through all the bytecodes

        # 5. Find the Samli representation

        pass

    @property
    def superclass_relationships(self) -> Dict[str, Set[str]]:
        """
        Return a dict-based tree structure that stores the
        relationships between classes.

        Usage:
        superclass_relationships[subclass] = {parent_class_1, parent_class_2, ...}
        """
        # 1. Send the command "icg"

        # 2. Iterate through all the lines

        # 3. Parse a node and its link to the children

        pass
