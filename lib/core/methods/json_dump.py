#!/usr/bin/env python
# Copyright (C) 2016 ToolsWatch.org
# This file is part of vFeed Correlated Threat & Vulnerability Community Database API Parser - http://www.toolswatch.org
# See the file 'LICENSE' for copying permission.

import json
from config.constants import title, author, build, repository, twitter, db
from lib.common.database import Database
from lib.common.utils import check_env, move_export
from lib.core.methods import *


class ExportJson(object):
    def __init__(self, cve):
        self.cve = cve.upper()
        self.db = db
        check_env(self.db)
        (self.cur, self.query) = Database(self.cve).db_init()
        self.data = Database(self.cve, self.cur, self.query).check_cve()
        self.vfeed_id = self.cve.replace('CVE', 'VFD')
        self.json_file = self.cve.replace('-', '_') + '.json'

    def json_dump(self):
        """ Snort method
        :return: JSON response with Snort ID, signature and category
        """
        # CVE basic information
        data = CveInfo(self.cve)
        info = json.loads(data.get_cve())
        cpe = json.loads(data.get_cpe())
        cwe = json.loads(data.get_cwe())
        capec = json.loads(data.get_capec())
        category = json.loads(data.get_category())

        # Reference information
        data = CveRef(self.cve)
        scip = json.loads(data.get_scip())
        osvdb = json.loads(data.get_osvdb())
        certvn = json.loads(data.get_certvn())
        bid = json.loads(data.get_bid())
        iavm = json.loads(data.get_iavm())
        refs = json.loads(data.get_refs())

        # Risk calculation
        data = CveRisk(self.cve)
        severity = json.loads(data.get_severity())

        # Patch Information
        data = CvePatches(self.cve)
        ms = json.loads(data.get_ms())
        kb = json.loads(data.get_kb())
        aixapar = json.loads(data.get_aixapar())
        redhat = json.loads(data.get_redhat())
        debian = json.loads(data.get_debian())
        ubuntu = json.loads(data.get_ubuntu())
        suse = json.loads(data.get_suse())
        gentoo = json.loads(data.get_gentoo())
        fedora = json.loads(data.get_fedora())
        mandriva = json.loads(data.get_mandriva())
        vmware = json.loads(data.get_vmware())
        cisco = json.loads(data.get_cisco())
        hp = json.loads(data.get_hp())

        # Scanners Information
        data = CveScanners(self.cve)
        nessus = json.loads(data.get_nessus())
        openvas = json.loads(data.get_openvas())
        oval = json.loads(data.get_oval())
        nmap = json.loads(data.get_nmap())

        # Exploitation Information
        data = CveExploit(self.cve)
        msf = json.loads(data.get_msf())
        saint = json.loads(data.get_saint())
        edb = json.loads(data.get_edb())
        elliot = json.loads(data.get_d2())

        # Rules Information
        data = CveRules(self.cve)
        snort = json.loads(data.get_snort())
        suricata = json.loads(data.get_suricata())

        json_export = {
            'vFeed': {'id': self.vfeed_id, 'Author': author, 'Product': title, 'Version': build, 'URL': repository,
                      'Contact': twitter},
            'Information': {'CVE': info, 'CPE': cpe, 'CWE': cwe, 'CAPEC': capec, 'Category': category},
            'References': {'SCIP': scip, 'OSVDB': osvdb, 'CertVN': certvn, 'BID': bid, 'IAVM': iavm,
                           'Other': {'References': refs}}, 'Risk': severity,
            'Patches': {'Microsoft Bulletins': ms, 'Microsoft KB': kb,
                        'IBM AIX Apar': aixapar, 'Redhat': redhat, 'Debian': debian,
                        'Ubuntu': ubuntu, 'Gentoo': gentoo, 'Suse': suse, 'Fedora': fedora,
                        'Mandriva': mandriva, 'Vmware': vmware, 'Cisco': cisco, 'HP': hp},
            'Scanners': {'Nessus': nessus, 'OpenVas': openvas, 'Oval': oval, 'Nmap': nmap},
            'Exploits': {'Metasploit': msf, 'Saint': saint, 'ExploitDB': edb, 'Elliot D2': elliot},
            'Rules': {'Snort': snort, 'Suricata': suricata}}

        print "[+] Exporting to JSON file %s" % self.json_file
        move_export(json_export, self.json_file)
        print "[!] %s moved to export repository" % self.json_file

        return json.dumps(json_export, indent=4, sort_keys=True)
