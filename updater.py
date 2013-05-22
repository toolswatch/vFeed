#!/usr/bin/env python

__author__ = 'NJ OUCHN'
__email__ = 'hacker@toolswatch.org'
__website__= 'http://www.toolswatch.org'
__release__ = 'vFeed b0.2'

import os
import sys
import urllib2
import tarfile

'''
updater.py -  vFeed Database Updater

Todo:

- read info from a configuration file
- check file integrity using a hash function

'''

def _updateDB(url):
    filename = url.split('/')[-1]
    u = urllib2.urlopen(url)
    f = open(filename, 'wb')
    meta = u.info()
    filesize = int(meta.getheaders("Content-Length")[0])
    print "[update] receiving %s Bytes: %s" % (filename, filesize)
    
    filesize_dl = 0
    block_sz = 8192
    while True:
        buffer = u.read(block_sz)
        if not buffer:
            break
    
        filesize_dl += len(buffer)
        f.write(buffer)
        status = r"%10d [%3.2f%%]" % (filesize_dl, filesize_dl * 100. / filesize)
        status = status + chr(8)*(len(status)+1)
        print status,       
    
    print ' '
    
def _uncompress(vfeed_db_compressed):
        
    if not os.path.isfile(vfeed_db_compressed):
        print '[error] ' + vfeed_db_compressed + ' not found'
        print '[info] Get manually your copy from %s' %vfeed_db_url
        exit(0)
    
    try:
        tar = tarfile.open(vfeed_db_compressed, 'r')
        tar.extract("vfeed.db",".")
        tar.close
        print '[info] ' + vfeed_db_compressed + ' extracted to vfeed.db'
    except:
        print '[error] Database not extracted'
        

def main():
    
    # Official URL
    vfeed_db_primary_url = 'http://www.toolswatch.org/vfeed/'
    vfeed_db_compressed= 'vfeed.db.tgz'
    vfeed_db = 'vfeed.db'

    print '[info] Downloading the recent vFeed Database %s from %s' %(vfeed_db_compressed,vfeed_db_primary_url)
    _updateDB(vfeed_db_primary_url+vfeed_db_compressed)
        
    print '[info] Decompressing %s ...' %vfeed_db_compressed
    _uncompress(vfeed_db_compressed)

    print '[info] Cleaning ' + vfeed_db_compressed
    os.remove(vfeed_db_compressed)

if __name__ == '__main__':
    main()