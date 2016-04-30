#!/usr/bin/env python
# Copyright (C) 2016 ToolsWatch.org
# This file is part of vFeed Vulnerability Database Community API Parser - http://www.toolswatch.org
# See the file 'LICENSE' for copying permission.

try:
    import sys
    import argparse
    from config.stats import Stats
    from lib.common.banner import banner
    from lib.core.search import Search
    from lib.core.update import Update
    from lib.migration.mongo import Migrate
    from config.constants import build, title
    from lib.common.utils import enum_classes
except ImportError, e:
    print("[!] Missing a dependency:"), str(e)
    sys.exit()

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-v", "--version", action="version",
                        version=".:. {0} .:. ".format(title) + "(ver {0})".format(build))
    parser.add_argument("-m", "--method", metavar=('Method', 'CVE'), type=str, help="Invoking multiple vFeed methods.",
                        nargs=2)
    parser.add_argument("-e", "--export", metavar=('type', 'CVE'), type=str, help="Export to XML or JSON the CVE id",
                        nargs=2)
    parser.add_argument("-s", "--search", metavar="id", type=str,
                        help="Search utility for CVE,CPE,CWE, OVAL or free text")
    parser.add_argument("--stats", metavar="get_stats / get_latest", type=str,
                        help="View the vFeed Database statistics", nargs=1)
    parser.add_argument("-u", "--update", help="Update the Vulnerability and Threat Database", action="store_true",
                        required=False)
    parser.add_argument("--list", help="Enumerate the list of available methods", action="store_true", required=False)
    parser.add_argument("--banner", help="Print vFeed banner", action="store_true", required=False)
    parser.add_argument("--migrate", help="Migration to MongoDB", action="store_true", required=False)
    args = parser.parse_args()

    if args.search:
        Search(args.search)
    elif args.update:
        Update().update()
    elif args.banner:
        banner()
    elif args.migrate:
        Migrate()
    elif args.stats:
        method_name = args.stats[0]
        if method_name == "get_stats" or method_name == "get_latest":
            result = getattr(Stats(), method_name)
            print result()
        else:
            print"[!] Unknown Method"
    elif args.list:
        enum_classes("list", "")
    elif args.method or args.export:
        if args.method:
            method_name = args.method[0]
            cve_id = args.method[1]
            result = enum_classes(method_name, cve_id)
            print result
        else:
            method_name = args.export[0]
            if method_name == "xml_dump" or method_name == "json_dump":
                cve_id = args.export[1]
                enum_classes(method_name, cve_id)
            else:
                print"[!] Unknown Method"
