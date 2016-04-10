#!/usr/bin/env python
# Copyright (C) 2016 ToolsWatch.org
# This file is part of vFeed Correlated Threat & Vulnerability Community Database API Parser - http://www.toolswatch.org
# See the file 'LICENSE' for copying permission.


import sys
import sqlite3
from config.constants import db
from lib.common.utils import check_env


class Database(object):
    def __init__(self, identifier, cursor="", query=""):
        self.identifier = identifier
        self.cur = cursor
        self.query = query
        self.db = db
        check_env(self.db)

    def db_stats(self):
        try:
            self.conn = sqlite3.connect(self.db)
            self.cur = self.conn.cursor()
            return self.cur, self.conn
        except Exception, e:
            print '[!] something occurred while opening the database', e
            sys.exit()

    def db_init(self):
        try:
            self.conn = sqlite3.connect(self.db)
            self.cur = self.conn.cursor()
            self.query = (self.identifier,)
            return self.cur, self.query
        except Exception, e:
            print '[!] something occurred while opening the database', e
            sys.exit()

    def check_cve(self):
        try:
            self.cur.execute('SELECT * FROM nvd_db WHERE cveid=?', self.query)
            self.data = self.cur.fetchone()
            if self.data is None:
                print '[!] %s is missed from vFeed Database' % self.identifier
                sys.exit("[+] Your database is maybe not up-to-date. run `vfeedcli.py --update`")
        except Exception, e:
            print '[exception]:', e
            sys.exit()
        return self.data
