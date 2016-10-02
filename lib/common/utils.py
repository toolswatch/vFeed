#!/usr/bin/env python
# Copyright (C) 2016 vFeed IO
# This file is part of vFeed Correlated Vulnerability & Threat Database API  - https://vfeed.io
# See the file 'LICENSE' for copying permission.

from __future__ import print_function
import os
import json
import shutil
import inspect
import commands

from config.constants import export_dir


def check_env(file):
    """
    check whether a file exists or not
    :param file:
    :return:
    """
    if not os.path.isfile(file):
        return False


def enum_classes(method_name, cve_id):
    """
    return list of functions into a class
    :param cve_id:
    :param method_name:
    :return: list of function
    """
    import lib.core.methods as functions

    method_found = False
    classes = []

    for name, obj in inspect.getmembers(functions, inspect.isclass):
        if inspect.isclass(obj):
            classes.append(obj)

    for my_class in classes:
        if method_name == "list":
            # Sanitize the class name.
            print("Built-in functions related to class:",
                  str(my_class).replace("class", "").replace("<", "").replace(">", "").split(".")[
                      4].replace("'", ""))
            method_found = True
        for function in enum_functions(my_class):
            if method_name == "list":
                if "__" not in function:
                    print("\t |---> ", function)
            else:
                if method_name == function:
                    result = getattr(my_class(cve_id), method_name)
                    return result()
    if not method_found:
        return "Use option '--list' to enumerate the available methods."


def enum_functions(class_name):
    """
    return list of functions in a class
    :param class_name
    :return: list of functions
    """
    functions = [attr for attr in dir(class_name) if inspect.ismethod(getattr(class_name, attr))]
    return functions


def move_export(json_export, json_file):
    """
    move exported JSON files to export repository
    :param json_export
    :param json_file
    :return: None
    """
    output_file = open(json_file, "w")
    dest_file = os.path.join(export_dir, json_file)
    json.dump(json_export, output_file, indent=2)

    if os.path.exists(dest_file):
        os.remove(dest_file)

    shutil.move(json_file, export_dir)

    return


def mongo_server():
    """ check whether the MongoDB is up and running
    :return: listing of processes
    """
    output = commands.getoutput('ps -A')
    return output
