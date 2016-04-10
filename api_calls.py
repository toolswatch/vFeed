#!/usr/bin/env python
# Copyright (C) 2016 ToolsWatch.org
# This file is part of vFeed Correlated Threat & Vulnerability Community Database API Parser - http://www.toolswatch.org
# See the file 'LICENSE' for copying permission.

# you can import class by class
# from lib.core.methods import CveInfo, CveRisk

import json
from lib.core.methods import *


cve = "CVE-2014-0160"
print "Basic information of", cve
info = CveInfo(cve).get_cve()
print info

print "CWE information related to", cve
cwe = CveInfo(cve).get_cwe()
print cwe

print "CPE information related to", cve
cpe = CveInfo(cve).get_cpe()
print cpe
print "Total of CPEs found is:", len(json.loads(cpe))

print "CVSS information related to", cve
cvss = CveRisk(cve).get_cvss()
print cvss

cve = "CVE-2008-4250"
print "Risk information related to", cve
print "Note that severity includes the CVSS v2 as well"
severity = CveRisk(cve).get_severity()
print severity

cve = "CVE-2015-0222"
print "Ubuntu patches related to", cve
ubuntu = CvePatches(cve).get_ubuntu()
print ubuntu

cve = "CVE-2008-4250"
print "Nessus information related to", cve
nessus = CveScanners(cve).get_nessus()
print nessus
print "Total of Nessus scripts found is:", len(json.loads(nessus))

cve = "CVE-2006-6077"
print "OVAL information related to", cve
oval = CveScanners(cve).get_oval()
print oval

cve = "CVE-2011-3402"
print "Metasploit information related to", cve
metasploit = CveExploit(cve).get_msf()
print metasploit

cve = "CVE-2004-0990"
print "Snort information related to", cve
snort = CveRules(cve).get_snort()
print snort

from lib.core.search import Search

cpe = "cpe:/a:invensys:foxboro"
print "Search for", cpe
Search(cpe)

cwe = "cwe-89"
print "Search for", cwe
Search(cwe)

cve = "CVE-2004-0990"
print "Search for", cve
Search(cve)

oval = "oval:org.mitre.oval:def:17538"
print "Search for", oval
Search(oval)

cve = "CVE-2004-0990"
export = ExportJson(cve).json_dump()
print export

print "Updating the vFeed database from your scripts"
from lib.core.update import Update
Update().update()
