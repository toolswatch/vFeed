#!/usr/bin/env python
# Copyright (C) 2015 ToolsWatch.org
# This file is part of vFeed Vulnerability Database Community API Parser - http://www.toolswatch.org
# See the file 'LICENSE' for copying permission

# DO NOT DELETE OR MODIFY.

import os

current_dir = os.path.abspath(os.path.dirname(__file__))
root_dir = os.path.normpath(os.path.join(current_dir, ".."))
export_dir = os.path.normpath(os.path.join(root_dir, "export"))

# vFeed Database information
title = "vFeed - The Correlated Vulnerability and Threat Database"
author = "NJ OUCHN"
twitter = "@toolswatch"
repository = "https://github.com/toolswatch/vFeed"
build = "0.6.0"

# Update Information
url_test = "http://www.toolswatch.org"
url = "http://www.toolswatch.org/vfeed/"
db = "vfeed.db"
db_compressed = "vfeed.db.tgz"
update_status = "update"

# Third party URLs
cve_url = "http://cve.mitre.org/cgi-bin/cvename.cgi?name="
cwe_url = "https://cwe.mitre.org/data/definitions/"
capec_url = "https://capec.mitre.org/data/definitions/"
osvdb_url = "http://www.osvdb.org/"
bid_url = "http://www.securityfocus.com/bid/"
ms_bulletin_url = "http://technet.microsoft.com/en-us/security/bulletin/"
kb_bulletin_url = "https://support.microsoft.com/en-us/kb/"
ibm_url = "http://www-01.ibm.com/support/docview.wss?uid=swg1"
redhat_url = "https://rhn.redhat.com/errata/"
redhat_oval_url = "https://www.redhat.com/security/data/oval/com.redhat.rhsa-"
bugzilla_url = "https://bugzilla.redhat.com/show_bug.cgi?id="
debian_url = "https://security-tracker.debian.org/tracker/"
suse_url = "https://www.suse.com/security/cve/"
ubuntu_url = "http://www.ubuntu.com/usn/"
gentoo_url = "https://security.gentoo.org/glsa/"
fedora_url = "https://admin.fedoraproject.org/updates/"
mandriva_url = "http://www.mandriva.com/security/advisories?name="
vmware_url = "https://www.vmware.com/security/advisories/"
edb_url = "http://www.exploit-db.com/exploits/"
oval_url = "http://oval.mitre.org/repository/data/getDef?id="
nmap_url = "https://nmap.org/nsedoc/scripts/"
