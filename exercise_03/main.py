import sys
sys.path.append(".")

import functools
import os.path
from typing import Any, List

import click

from exercise_03.core.rzapkinfo import RizinImp


@click.command(no_args_is_help=True)
@click.option(
    "-a",
    "--apk",
    type=click.Path(exists=True, file_okay=True, dir_okay=False),
    required=True,
)
@click.option("-m", "--method")
@click.option("--list-permissions", is_flag=True)
@click.option("--list-methods", is_flag=True)
@click.option("--find-upper", is_flag=True)
@click.option("--find-lower", is_flag=True)
@click.option("--get-bytecode", is_flag=True)
@click.option("--list-inheritance", is_flag=True)
def entry_point(
    apk,
    method,
    list_permissions,
    list_methods,
    find_upper,
    find_lower,
    get_bytecode,
    list_inheritance,
):
    # APK
    apk = os.path.realpath(apk)
    print(f"APK Path: {apk}")
    print("")

    apkinfo = RizinImp(apk)

    # Method
    if method:
        target = parse_method(apkinfo, method)
        if not target:
            print(f"Cannot find method {target}")
            return

        print(f"Method: {target}")
    elif any([find_upper, find_lower, list_inheritance, get_bytecode]):
        print("Please provide a target method via --method")
        return

    if list_permissions:
        display_list(apkinfo.permissions, "Permissions")

    if list_methods:
        display_list(apkinfo.all_methods, "Methods")

    if find_upper:
        display_list(apkinfo.upperfunc(target), "Crossreferences TO function")

    if find_lower:
        display_list(apkinfo.lowerfunc(target), "Crossreferences FROM function")

    if get_bytecode:
        display_list(apkinfo.get_method_bytecode(target), "Bytecodes")

    if list_inheritance:
        print("Class inheritance list")
        print("--------------------")

        for index, entry in enumerate(apkinfo.superclass_relationships.items(), start=1):
            child, parents = entry
            print(f"{index:2>}. {child}")
            print(f"\t{parents}")
        print("")


@functools.lru_cache
def parse_method(apkinfo, method_str):
    generator = filter(lambda m: m.full_name == method_str, apkinfo.all_methods)
    return next(generator, None)


def display_list(data_list: List[Any], title: str):
    print(title)
    print("---------------------------")

    for index, entry in enumerate(data_list):
        print(f"{index:2>}. {entry}")

    print("")


if __name__ == "__main__":
    entry_point()