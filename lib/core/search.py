#!/usr/bin/env python
# Copyright (C) 2016 ToolsWatch.org
# This file is part of vFeed Correlated Threat & Vulnerability Community Database API Parser - http://www.toolswatch.org
# See the file 'LICENSE' for copying permission.

import json
import sys
import re
from config.constants import db
from lib.core.methods import CveExploit
from lib.common.database import Database


class Search(object):
    def __init__(self, query):
        self.query = query
        self.db = db
        self.detect_entry()

    def detect_entry(self):
        """ detect user input entry (CVE, CPE, OVAL or CWE). Used for Search method
        :return: type of entry
        """
        cve_entry = re.compile("CVE-\d+-\d+", re.IGNORECASE)
        cpe_entry = re.compile("cpe:/[a-zA-Z0-9]", re.IGNORECASE)
        cwe_entry = re.compile("CWE-\\d+", re.IGNORECASE)
        oval_entry = re.compile("oval:org.[a-zA-Z0-9]", re.IGNORECASE)

        if re.findall(cve_entry, self.query):
            self.search_cve()
        elif re.findall(cpe_entry, self.query):
            self.search_cpe()
        elif re.findall(cwe_entry, self.query):
            self.search_cwe()
        elif re.findall(oval_entry, self.query):
            self.search_oval()
        else:
            self.search_summary()

        return

    def search_cve(self):
        """ Simple method to search for CVE occurrences
        :return: CVE summary
        """
        self.cve = self.query.upper()
        (self.cur, self.query) = Database(self.cve).db_init()
        self.data = Database(self.cve, self.cur, self.query).check_cve()

        print '[+] Querying information for %s ...' % self.cve
        self.cur.execute("SELECT * from nvd_db where cveid=?", (self.cve,))
        self.cve_data = self.cur.fetchall()

        for data in self.cve_data:
            print data[3]

        print "\n[?] Hint \nTry:\n `vfeedcli.py --method get_cve %s` " % self.cve
        print "or\n `vfeedcli.py --export json_dump %s`" % self.cve

    def search_cpe(self):
        """
        Simple method to search for CPEs
        :return: CVEs (exploits are highlighted when available)
        """
        self.cpe = self.query.lower()
        (self.cur, self.query) = Database(self.cpe).db_init()

        self.cur.execute("SELECT count(distinct cveid) from cve_cpe where cpeid like ?", ('%' + self.cpe + '%',))
        self.count_cve = self.cur.fetchone()
        self.cur.execute("SELECT count(distinct cpeid) from cve_cpe where cpeid like ?", ('%' + self.cpe + '%',))
        self.count_cpe = self.cur.fetchone()

        if self.count_cve[0] == 0:
            print '[!] Occurrence not found'
            sys.exit()

        print '[+] Gathering information ... '
        self.cur.execute("SELECT distinct cpeid from cve_cpe where cpeid like ? ORDER BY cpeid DESC",
                         ('%' + self.cpe + '%',))
        self.cpe_datas = self.cur.fetchall()

        for i in range(0, self.count_cpe[0]):
            self.mycpe = self.cpe_datas[i][0]
            print '\t[+] %s' % self.mycpe
            self.cur.execute("SELECT cveid from cve_cpe where cpeid=?", (self.mycpe,))
            self.cve_datas = self.cur.fetchall()
            for self.cve_data in self.cve_datas:
                self.mycve = self.cve_data[0]
                print '\t\t|-> %s' % self.mycve
                self.check_exploit(self.mycve)
        print '[+] Printing search statistics for %s' % self.cpe
        print '\t [-] Total Unique CVEs        [%s] ' % self.count_cve
        print '\t [-] Total Found CPEs         [%s] ' % self.count_cpe

    def search_cwe(self):
        """
        Simple method to search CWEs
        :return: CVEs related to CWE
        """
        self.cwe = self.query.upper()
        (self.cur, self.query) = Database(self.cwe).db_init()

        self.cur.execute("SELECT count(distinct cveid) from cve_cwe where cweid=?", (self.cwe,))
        self.count_cve = self.cur.fetchone()
        if self.count_cve[0] == 0:
            print '[!] Occurrence not found'
            sys.exit()

        print '[+] Gathering information ... '
        self.cur.execute("SELECT cveid from cve_cwe where cweid=? ORDER BY cveid DESC", (self.cwe,))
        cve_data = self.cur.fetchall()
        for data in cve_data:
            self.mycve = data[0]
            print '\t\t|-> %s' % self.mycve
            self.check_exploit(self.mycve)

        print '[+] Printing search statistics for %s' % self.cwe
        print '\t [-] Total unique found CVEs: %s' % self.count_cve

    def search_oval(self):
        """
        Simple method to search OVAL
        :return: CVEs related to OVAL
        """
        self.oval = self.query.lower()
        (self.cur, self.query) = Database(self.oval).db_init()

        self.cur.execute("SELECT count(distinct cveid) from map_cve_oval where ovalid=?", (self.oval,))
        self.count_cve = self.cur.fetchone()
        self.cur.execute("SELECT count(distinct ovalid) from map_cve_oval where ovalid=?", (self.oval,))
        self.count_oval = self.cur.fetchone()

        if self.count_cve[0] == 0:
            print '[!] Occurrence not found'
            sys.exit()
        print '[+] Gathering information ... '

        self.cur.execute("SELECT distinct ovalid from map_cve_oval where ovalid =? ORDER BY ovalid DESC", (self.oval,))
        self.oval_datas = self.cur.fetchall()

        for i in range(0, self.count_oval[0]):
            self.myoval = self.oval_datas[i][0]
            print '\t[+] %s' % self.myoval

            self.cur.execute("SELECT cveid from map_cve_oval where ovalid=?", (self.myoval,))
            self.cve_datas = self.cur.fetchall()
            for self.cve_data in self.cve_datas:
                self.mycve = self.cve_data[0]
                print '\t\t|-> %s' % self.mycve
                self.check_exploit(self.mycve)

        print '[+] Printing search statistics for %s' % self.oval
        print '\t [-] Total Unique CVEs        [%s] ' % self.count_cve
        print '\t [-] Total Found OVAL         [%s] ' % self.count_oval

    def search_summary(self):
        self.entry = self.query.lower()
        (self.cur, self.conn) = Database(None).db_init()

        print '[+] Querying information for %s ...' % self.entry
        self.cur.execute("SELECT * from nvd_db where summary like ? ORDER BY cveid DESC",
                         ('%' + self.entry + '%',))

        self.entry_data = self.cur.fetchall()
        for data in self.entry_data:
            print '|-> ' + data[0] + ': ' + data[3]
            print ''

    @staticmethod
    def check_exploit(cve):
        msf = CveExploit(cve).get_msf()
        edb = CveExploit(cve).get_edb()
        if len(json.loads(msf)) != 0:
            print "\t\t\t[!] Metasploit exploit found."
        if len(json.loads(edb)) != 0:
            print "\t\t\t[!] Exploit-DB PoC found."
