#!/usr/bin/env python
# Copyright (C) 2016 ToolsWatch.org
# This file is part of vFeed Correlated Threat & Vulnerability Community Database API Parser - http://www.toolswatch.org
# See the file 'LICENSE' for copying permission.


import json
from config.constants import *
from lib.common.database import Database
from lib.common.utils import check_env


class CvePatches(object):
    def __init__(self, cve):
        self.cve = cve.upper()
        self.db = db
        check_env(self.db)
        (self.cur, self.query) = Database(self.cve).db_init()
        self.data = Database(self.cve, self.cur, self.query).check_cve()

    def get_ms(self):
        """ Microsoft method
        :return: JSON response with Microsoft Security Bulletins ID and link
        """
        self.ms = []
        self.cur.execute('SELECT * FROM map_cve_ms WHERE cveid=?', self.query)

        for self.data in self.cur.fetchall():
            item = {'id': str(self.data[0]), 'title': str(self.data[1]), 'url': ms_bulletin_url + str(self.data[0])}
            self.ms.append(item)

        return json.dumps(self.ms, indent=4, sort_keys=True)

    def get_kb(self):
        """ Microsoft method
        :return: JSON response with Microsoft KB ID and link
        """
        self.kb = []
        self.cur.execute(
            'SELECT * FROM map_cve_mskb WHERE cveid=?', self.query)

        for self.data in self.cur.fetchall():
            item = {'id': str(self.data[0]), 'title': str(self.data[1]), 'url': kb_bulletin_url + str(self.data[0])}
            self.kb.append(item)

        return json.dumps(self.kb, indent=4, sort_keys=True)

    def get_aixapar(self):
        """ AIX APAR method
        :return: JSON response with IBM AIXapar KB ID and link
        """
        self.aixapar = []

        self.cur.execute(
            'SELECT * FROM map_cve_aixapar WHERE cveid=?', self.query)

        for self.data in self.cur.fetchall():
            item = {'id': str(self.data[0]), 'url': ibm_url + str(self.data[0])}
            self.aixapar.append(item)

        return json.dumps(self.aixapar, indent=4, sort_keys=True)

    def get_redhat(self):
        """ Redhat  method
        :return: JSON response with Redhat / Bugzilla id, OVAL, title and links
        """
        self.redhat = []
        self.cur.execute(
            'SELECT * FROM map_cve_redhat WHERE cveid=?', self.query)

        for self.data in self.cur.fetchall():
            item = {"Redhat": {"id": str(self.data[0]), 'oval': str(self.data[1]), 'title': str(self.data[2]),
                               'url': redhat_url + str.replace(str(self.data[0]), ':', '-') + ".html"}}
            self.redhat.append(item)
            # Querying the mapped redhat id and bugzilla id table
            self.query2 = (str(self.data[0]),)
            self.cur.execute('SELECT * FROM map_redhat_bugzilla WHERE redhatid=?', self.query2)

            for self.data2 in self.cur.fetchall():
                item2 = {"bugzilla": {"id": str(self.data2[1]), 'issue date': str(self.data2[0]),
                                      'title': str(self.data2[2]), "associated redhat": str(self.data[0]),
                                      "url": bugzilla_url + str(self.data2[1])}}
                self.redhat.append(item2)

        return json.dumps(self.redhat, indent=4, sort_keys=True)

    def get_debian(self):
        """ Debian  method
        :return: JSON response with Debian id and link
        """
        self.debian = []
        self.cur.execute(
            'SELECT * FROM map_cve_debian WHERE cveid=?', self.query)

        for self.data in self.cur.fetchall():
            item = {'id': self.data[0], 'url': debian_url + str(self.data[0])}
            self.debian.append(item)

        return json.dumps(self.debian, indent=4, sort_keys=True)

    def get_suse(self):
        """ Suse  method
        :return: JSON response with Suse id and link
        """
        self.suse = []
        self.cur.execute(
            'SELECT * FROM map_cve_suse WHERE cveid=?', self.query)

        for self.data in self.cur.fetchall():
            item = {'id': self.data[0], 'url': suse_url + self.cve + ".html"}

            self.suse.append(item)

        return json.dumps(self.suse, indent=4, sort_keys=True)

    def get_ubuntu(self):
        """ Ubuntu  method
        :return: JSON response with Ubuntu id and link
        """
        self.ubuntu = []
        self.cur.execute(
            'SELECT * FROM map_cve_ubuntu WHERE cveid=?', self.query)

        for self.data in self.cur.fetchall():
            item = {'id': self.data[0], 'url': ubuntu_url + str(self.data[0])}
            self.ubuntu.append(item)

        return json.dumps(self.ubuntu, indent=4, sort_keys=True)

    def get_gentoo(self):
        """ Gentoo  method
        :return: JSON response with Gentoo id
        """
        self.gentoo = []
        self.cur.execute(
            'SELECT * FROM map_cve_gentoo WHERE cveid=?', self.query)

        for self.data in self.cur.fetchall():
            item = {'id': self.data[0], 'url': gentoo_url + str.replace(str(self.data[0]), 'GLSA-', '')}
            self.gentoo.append(item)

        return json.dumps(self.gentoo, indent=4, sort_keys=True)

    def get_fedora(self):
        """ fedora  method
        :return: JSON response with Fedora id
        """
        self.fedora = []
        self.cur.execute(
            'SELECT * FROM map_cve_fedora WHERE cveid=?', self.query)

        for self.data in self.cur.fetchall():
            item = {'id': str(self.data[0]), 'url': fedora_url + str(self.data[0])}
            self.fedora.append(item)

        return json.dumps(self.fedora, indent=4, sort_keys=True)

    def get_mandriva(self):
        """ mandriva  method
        :return: JSON response with Mandriva id
        """
        self.mandriva = []
        self.cur.execute(
            'SELECT * FROM map_cve_mandriva WHERE cveid=?', self.query)

        for self.data in self.cur.fetchall():
            item = {'id': str(self.data[0]), 'url': mandriva_url + str(self.data[0])}
            self.mandriva.append(item)

        return json.dumps(self.mandriva, indent=4, sort_keys=True)

    def get_vmware(self):
        """ vmware  method
        :return: JSON response with VMware id
        """
        self.vmware = []
        self.cur.execute(
            'SELECT * FROM map_cve_vmware WHERE cveid=?', self.query)

        for self.data in self.cur.fetchall():
            item = {'id': str(self.data[0]), 'url': vmware_url + str(self.data[0]) + '.html'}
            self.vmware.append(item)

        return json.dumps(self.vmware, indent=4, sort_keys=True)

    def get_cisco(self):
        """ cisco  method
        :return: JSON response with Cisco id
        """
        self.cisco = []
        self.cur.execute('SELECT * FROM map_cve_cisco WHERE cveid=?', self.query)

        for self.data in self.cur.fetchall():
            item = {'id': str(self.data[0])}
            self.cisco.append(item)

        return json.dumps(self.cisco, indent=4, sort_keys=True)

    def get_hp(self):
        """ HP  method
        :return: JSON response with HP id
        """
        self.hp = []
        self.cur.execute(
            'SELECT * FROM map_cve_hp WHERE cveid=?', self.query)

        for self.data in self.cur.fetchall():
            item = {'id': str(self.data[0]), 'url': str(self.data[1])}
            self.hp.append(item)

        return json.dumps(self.hp, indent=4, sort_keys=True)
