#!/usr/bin/env python
# Copyright (C) 2016 ToolsWatch.org
# This file is part of vFeed Correlated Threat & Vulnerability Community Database API Parser - http://www.toolswatch.org
# See the file 'LICENSE' for copying permission.

import json
from config.constants import nmap_url, oval_url
from lib.common.database import Database


class CveScanners(object):
    def __init__(self, cve):
        self.cve = cve.upper()
        (self.cur, self.query) = Database(self.cve).db_init()
        self.data = Database(self.cve, self.cur, self.query).check_cve()

    def get_nessus(self):
        """ Nessus method
        :return: JSON response with Nessus ID, name, file and family
        """
        self.nessus = []
        self.cur.execute(
            'SELECT * FROM map_cve_nessus WHERE cveid=?', self.query)

        for self.data in self.cur.fetchall():
            item = {'id': str(self.data[0]), 'file': str(self.data[1]), 'name': str(self.data[2]),
                    'family': str(self.data[3])}
            self.nessus.append(item)

        return json.dumps(self.nessus, indent=4, sort_keys=True)

    def get_openvas(self):
        """ OpenVAS method
        :return: JSON response with OpenVAS ID, name, file and family
        """
        self.openvas = []
        self.cur.execute(
            'SELECT * FROM map_cve_openvas WHERE cveid=?', self.query)

        for self.data in self.cur.fetchall():
            item = {'id': str(self.data[0]), 'file': str(self.data[1]), 'name': str(self.data[2]),
                    'family': str(self.data[3])}
            self.openvas.append(item)

        return json.dumps(self.openvas, indent=4, sort_keys=True)

    def get_nmap(self):
        """ Nmap method
        :return: JSON response with Nmap file, family and url
        """
        self.nmap = []
        self.cur.execute(
            'SELECT * FROM map_cve_nmap WHERE cveid=?', self.query)

        for self.data in self.cur.fetchall():
            item = {'file': str(self.data[0]), 'family': str(self.data[1]).replace('"', '').strip(),
                    'url': nmap_url + str(self.data[0]).replace(".nse", ".html")}
            self.nmap.append(item)

        return json.dumps(self.nmap, indent=4, sort_keys=True)

    def get_oval(self):
        """ OVAL method
        :return: JSON response with OVAL id, class, title and file
        """
        self.oval = []
        self.cur.execute(
            'SELECT * FROM map_cve_oval WHERE cveid=?', self.query)
        for self.data in self.cur.fetchall():
            item = {'id': self.data[0], 'class': self.data[1], 'title': self.data[2].encode('ascii', 'ignore'),
                    'url': oval_url + self.data[0]}
            self.oval.append(item)

        return json.dumps(self.oval, indent=4, sort_keys=True)
