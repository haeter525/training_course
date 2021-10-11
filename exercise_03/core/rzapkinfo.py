import os.path
import tempfile
import zipfile
from functools import cached_property
from typing import *

import rzpipe
from exercise_03.core.methodobject import MethodObject


class RizinImp:
    def __init__(self, apk_filepath):
        # Acquire tmp folder
        self._tmp_dir = tempfile.mkdtemp()

        # Extract all contents into tmp
        with zipfile.ZipFile(self.apk_filepath) as apk:
            apk.extractall(path=self._tmp_dir)

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
        # TODO: Implement this with AXML Reader
        pass

    @property
    def all_methods(self) -> Set[MethodObject]:
        """
        Return all methods including Android native API and custom methods from given APK.

        :return: a set of all method MethodObject
        """
        # TODO: Implement this with command 'isj'
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
        # TODO: Implement this with command 'isj'
        pass

    def _get_method_by_address(self, address: int) -> MethodObject:
        # TODO: Implememt this.
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

    def get_method_bytecode(self, method_object: MethodObject) -> Set[str]:
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
