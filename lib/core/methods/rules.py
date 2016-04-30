#!/usr/bin/env python
# Copyright (C) 2016 ToolsWatch.org
# This file is part of vFeed Correlated Threat & Vulnerability Community Database API Parser - http://www.toolswatch.org
# See the file 'LICENSE' for copying permission.
import json
from lib.common.database import Database


class CveRules(object):
    def __init__(self, cve):
        self.cve = cve.upper()
        (self.cur, self.query) = Database(self.cve).db_init()
        self.data = Database(self.cve, self.cur, self.query).check_cve()

    def get_snort(self):
        """ Snort method
        :return: JSON response with Snort ID, signature and category
        """
        self.snort = []
        self.cur.execute('SELECT * FROM map_cve_snort WHERE cveid=?', self.query)

        for self.data in self.cur.fetchall():
            item = {'id': str(self.data[0]), 'signature': str(self.data[1]), 'category': str(self.data[2])}
            self.snort.append(item)

        return json.dumps(self.snort, indent=4, sort_keys=True)

    def get_suricata(self):
        """ Suricata method
        :return: JSON response with Suricata ID, signature and category
        """
        self.suricata = []
        self.cur.execute('SELECT * FROM map_cve_suricata WHERE cveid=?', self.query)

        for self.data in self.cur.fetchall():
            item = {'id': str(self.data[0]), 'signature': str(self.data[1]), 'classtype': str(self.data[2])}
            self.suricata.append(item)

        return json.dumps(self.suricata, indent=4, sort_keys=True)
