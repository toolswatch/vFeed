#!/usr/bin/env python
# Copyright (C) 2015 ToolsWatch.org
# This file is part of vFeed Vulnerability Database Community API Parser - http://www.toolswatch.org
# See the file 'LICENSE' for copying permission.
import os
import sys
import urllib2
import tarfile
from config.constants import db, db_compressed, url, url_test, update_status, \
    config_dir, db_local, db_compressed_local, update_status_local
from lib.common.utils import checksum


class Update(object):
    def __init__(self):
        self.db = db
        self.db_compressed = db_compressed
        self.db_local = db_local
        self.db_compressed_local = db_compressed_local
        self.config_dir = config_dir
        self.url_test = url_test
        self.db_url = url
        self.db_update = update_status
        self.db_update_local = update_status_local
        self.db_download = self.db_url + self.db_compressed
        self.db_status = self.db_url + self.db_update
        self.db_status_local = os.path.join(config_dir, update_status)
        self.remote_db = self.db_url + self.db_compressed

    def update(self):
        """
        Initiate the update process.
        :return:
        """

        print "[+] Checking connectivity to", self.db_url
        try:
            if urllib2.urlopen(self.url_test):
                if not os.path.isdir(self.config_dir):
                    os.makedirs(self.config_dir)
                if not os.path.isfile(self.db_local):
                    print "[+] New install. Downloading the Correlated Vulnerability Database."
                    self.download(self.remote_db, self.db_compressed_local)
                    print '\n[+] Installing %s ...' % self.db_compressed
                    self.uncompress()
                    self.clean()
                    sys.exit(1)
                if os.path.isfile(self.db_local):
                    print "[+] Checking for the latest vFeed Vulnerability Database"
                    self.check_status()
        except urllib2.URLError as e:
            print "[!] Connection error: ", e.reason
            sys.exit()

    def download(self, url, dest=None):
        """
        This function was found in internet. So thanks to its author wherever he is.
        Just improve it a little by adding the percentage display
        :param url:
        :return:
        """

        self.filename = dest or url.split('/')[-1]
        self.local = os.path.basename(dest)
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
                self.filesize_dl, self.filesize, self.local, self.filesize_dl * 100. / self.filesize))
            sys.stdout.flush()
        self.f.close()

    def uncompress(self):
        """

        :return:
        """

        if not os.path.isfile(self.db_compressed_local):
            print '[error] ' + self.db_compressed_local + ' not found'
            sys.exit()
        try:
            self.tar = tarfile.open(self.db_compressed_local, 'r:gz')
            self.tar.extractall(self.config_dir)
        except Exception, e:
            print '[error] Database not extracted ', e

    def check_status(self):
        """ Check the remote update status and
        update the existing vfeed database if needed
        """
        self.download(self.db_status, self.db_status_local)
        self.hashLocal = checksum(self.db_local)
        with open(self.db_status_local, 'r') as f:
            self.output = f.read()
            self.hashRemote = self.output.split(',')[1]

        if self.hashRemote != self.hashLocal:
            print '\n[+] Downloading the recent vFeed Vulnerability Database update'
            self.download(self.remote_db, self.db_compressed_local)
            print '\n[+] Decompressing %s ' % self.db_compressed_local
            self.uncompress()

        if self.hashRemote == self.hashLocal:
            print '\n[+] You have the latest %s Vulnerability Database' % self.db

        self.clean()

    def clean(self):
        """ Clean the tgz, update.dat temporary file and move database to repository
        """
        print '[+] Cleaning compressed database and update file'
        try:
            if os.path.isfile(self.db_compressed_local):
                os.remove(self.db_compressed_local)
            if os.path.isfile(self.db_update_local):
                os.remove(self.db_update_local)
        except Exception, e:
            print '[!] Already cleaned', e
