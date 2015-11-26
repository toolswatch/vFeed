#!/usr/bin/env python
# Copyright (C) 2015 ToolsWatch.org
# This file is part of vFeed Vulnerability Database Community API Parser - http://www.toolswatch.org
# See the file 'LICENSE' for copying permission.
import os
import sys
import urllib2
import tarfile
from config.constants import db, db_compressed, url, url_test, update_status
from lib.common.utils import checksum


class Update(object):
    def __init__(self):
        self.db = db
        self.db_compressed = db_compressed
        self.url_test = url_test
        self.db_url = url
        self.db_update = update_status
        self.db_download = self.db_url + self.db_compressed
        self.db_status = self.db_url + self.db_update
        self.remote_db = self.db_url + self.db_compressed

    def update(self):
        """
        Initiate the update process.
        :return:
        """

        print "[+] Checking connectivity to", self.db_url
        try:
            if urllib2.urlopen(self.url_test):
                if not os.path.isfile(self.db):
                    print "[+] New install. Downloading the Correlated Vulnerability Database."
                    self.download(self.remote_db)
                    print '\n[+] Installing %s ...' % self.db_compressed
                    self.uncompress()
                    self.clean()
                    sys.exit(1)
                if os.path.isfile(self.db):
                    print "[+] Checking for the latest vFeed Vulnerability Database"
                    self.check_status()
        except urllib2.URLError as e:
            print "[!] Connection error: ", e.reason
            sys.exit()

    def download(self, url):
        """
        This function was found in internet. So thanks to its author wherever he is.
        Just improve it a little by adding the percentage display
        :param url:
        :return:
        """

        self.filename = url.split('/')[-1]
        self.u = urllib2.urlopen(url)
        self.f = open(self.filename, 'wb')
        self.meta = self.u.info()
        self.filesize = int(self.meta.getheaders("Content-Length")[0])
        self.filesize_dl = 0
        self.block_sz = 8192
        while True:
            sys.stdout.flush()
            self.buffer = self.u.read(self.block_sz)
            if not self.buffer:
                break

            self.filesize_dl += len(self.buffer)
            self.f.write(self.buffer)
            self.status = r"%10d [%3.0f %%]" % (self.filesize_dl, self.filesize_dl * 100. / self.filesize)
            self.status += chr(8) * (len(self.status) + 1)
            sys.stdout.write("\r[+] Receiving %d out of %s Bytes of %s (%3.0f %%)" % (
                self.filesize_dl, self.filesize, self.filename, self.filesize_dl * 100. / self.filesize))
            sys.stdout.flush()
        self.f.close()

    def uncompress(self):
        """

        :return:
        """

        if not os.path.isfile(self.db_compressed):
            print '[error] ' + self.db_compressed + ' not found'
            sys.exit()
        try:
            self.tar = tarfile.open(self.db_compressed, 'r:gz')
            self.tar.extractall('.')
        except Exception, e:
            print '[error] Database not extracted ', e

    def check_status(self):
        """ Check the remote update status and
        update the existing vfeed database if needed
        """
        self.download(self.db_status)
        self.hashLocal = checksum(self.db)
        with open(self.db_update, 'r') as f:
            self.output = f.read()
            self.hashRemote = self.output.split(',')[1]

        if self.hashRemote != self.hashLocal:
            print '\n[+] Downloading the recent vFeed Vulnerability Database update'
            self.download(self.remote_db)
            print '\n[+] Decompressing %s ' % self.db_compressed
            self.uncompress()

        if self.hashRemote == self.hashLocal:
            print '\n[+] You have the latest %s Vulnerability Database' % self.db

        self.clean()

    def clean(self):
        """ Clean the tgz, update.dat temporary file and move database to repository
        """
        print '[+] Cleaning compressed database and update file'
        try:
            if os.path.isfile(self.db_compressed):
                os.remove(self.db_compressed)
            if os.path.isfile(self.db_update):
                os.remove(self.db_update)
        except Exception, e:
            print '[!] Already cleaned', e
