from functools import cached_property
from typing import *
from exercise_03.structure.methodobject import MethodObject

import os.path
import zipfile
import tempfile

class RizinImp:
    def __init__(self, apk_filepath):
        # Acquire tmp folder
        self._tmp_dir = tempfile.mkdtemp()

        # Extract all contents into tmp
        with zipfile.ZipFile(self.apk_filepath) as apk:
            apk.extractall(path=self._tmp_dir)

            self._manifest = os.path.join(self._tmp_dir, "AndroidManifest.xml")
            
            self._dex_list = [
                os.path.join(self._tmp_dir, filename)
                for filename in apk.namelist()
                if filename.startswith("classes") and filename.endswith(".dex")
            ]

    @cached_property
    def permissions(self) -> List[str]:
        """
        Return all permissions from given APK.

        :return: a list of all permissions
        """
        permission_list = []

        # Initialize AXML Reader
        axml_reader = AxmlReader(self._manifest)

        # Iterator through all XML Structures
        for structure in axml_reader:
            # Get the name value of a structure
            name_value = structure.get('Name', None)

            # Check if the structures defines a permission
            if name_value and axml_reader.get_string(name_value) == "uses-permission":
                # Get the attributes of the XML structure
                attributes = axml_reader.get_attributes(structure)

                if not attributes:
                    break

                # Get the permission
                str_value = attributes[0]["Value"]
                permission = axml_reader.get_string(str_value)

                # Append to the list
                permission_list.append(permission)

        return permission_list

    @property
    def all_methods(self) -> Set[MethodObject]:
        """
        Return all methods including Android native API and custom methods from given APK.

        :return: a set of all method MethodObject
        """
        # TODO: Implement this with command 'isj'
        pass

    @property
    def android_apis(self) -> Generator[None, None, MethodObject]:
        """
        Return all Android native APIs from given APK.

        :return: a set of all Android native APIs MethodObject
        """
        return (
            method
            for method in self.all_methods
            if method.is_android_api() and method.cache.is_imported
        )

    @property
    def custom_methods(self) -> Generator[None, None, MethodObject]:
        """
        Return all custom methods from given APK.

        :return: a set of all custom methods MethodObject
        """
        return (
            method
            for method in self.all_methods
            if not method.is_imported
        )


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
        # TODO: Implement this with command 'isj'
        pass

    def upperfunc(self, method_object: MethodObject) -> Set[MethodObject]:
        """
        Return the xref from method from given MethodObject instance.

        :param method_object: the MethodObject instance
        :return: a set of all xref from functions
        """
        # TODO: Implement this with command 'axtj'
        pass

    def lowerfunc(self, method_object: MethodObject) -> Set[MethodObject]:
        """
        Return the xref from method from given MethodObject instance.

        :param method_object: the MethodObject instance
        :return: a set of all xref from functions
        """
        # TODO: Implement this with command 'axffj'
        pass

    def get_method_bytecode(self, method_object: MethodObject) -> Set[MethodObject]:
        """
        Return the corresponding bytecode according to the
        given class name and method name.

        :param method_object: the MethodObject instance
        :return: a generator of all bytecode instructions
        """
        # TODO: Implement this with command 'pdfj'
        pass

    @property
    def superclass_relationships(self) -> Dict[str, Set[str]]:
        """
        Return a dict-based tree structure that stores the
        relationships between classes.

        Usage:
        superclass_relationships[subclass] = {parent_class_1, parent_class_2, ...}
        """
        # TODO: Implement this with command 'icg'
        pass