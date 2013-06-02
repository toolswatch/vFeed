#!/usr/bin/env python

import os
import urllib2
import tarfile
import hashlib

from vfeed import config


'''
vfeed_update.py -  vFeed Database Updater

'''
def checksumfile(_file):
    '''
    returning the sha1 hash value 
    '''
    sha1 = hashlib.sha1()
    f = open(_file, 'rb')
    try:
        sha1.update(f.read())
    finally:
        f.close()
    return sha1.hexdigest()
    
def _checkDBversion(vfeed_db_primary_url,updateStatus,vfeed_db,vfeed_db_compressed):
    '''
    updating the existing vfeed database if needed
    '''
    url = vfeed_db_primary_url + updateStatus
    _updateDB(url)     
    hashLocal = checksumfile(vfeed_db)
    with open(updateStatus,'r') as f:
        output = f.read()
        hashRemote = output.split(',')[1]
    
    if hashRemote <> hashLocal:
        print '[New Update] Downloading the recent vFeed Database %s from %s' %(vfeed_db_compressed,vfeed_db_primary_url)
        _updateDB(vfeed_db_primary_url+vfeed_db_compressed)
    
        print '[info] Decompressing %s ...' %vfeed_db_compressed
        _uncompress(vfeed_db_compressed)
    
        print '[info] Cleaning ' + vfeed_db_compressed
        os.remove(vfeed_db_compressed)
        exit(0)
        
    if hashRemote == hashLocal:
        print '[info] You have the latest %s vulnerability database' %vfeed_db
        
    
def _updateDB(url):
    '''
    This function was found on internet.
    So thanks to its author whenever he is.
    '''
    
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
    '''
    uncompress the tgz db
    '''    
    if not os.path.isfile(vfeed_db_compressed):
        print '[error] ' + vfeed_db_compressed + ' not found'
        print '[info] Get manually your copy from %s' % config.database['primary']['url']
        exit(0)
    
    try:
        tar = tarfile.open(vfeed_db_compressed, 'r')
        tar.extract("vfeed.db",".")
        tar.close
        print '[info] ' + vfeed_db_compressed + ' extracted to vfeed.db'
    except:
        print '[error] Database not extracted'
        

def main():
    
    configData = config.database['primary']
    
    vfeed_db_primary_url =  configData['url']
    vfeed_db_compressed  = configData['vfeed_db_compressed']
    vfeed_db  = configData['vfeed_db']
    updateStatus = configData['updateStatus']
    
    if not os.path.isfile(vfeed_db):
        print '[install] First time %s Database download ...' %vfeed_db
        _updateDB(vfeed_db_primary_url+vfeed_db_compressed)
        print '[info] Decompressing %s ...' %vfeed_db_compressed
        _uncompress(vfeed_db_compressed)
        print '[info] Cleaning ' + vfeed_db_compressed
        os.remove(vfeed_db_compressed)
        exit(0)
        
    if os.path.isfile(vfeed_db):
        print '[info] Checking for the latest %s ' %vfeed_db
        _checkDBversion(vfeed_db_primary_url,updateStatus,vfeed_db,vfeed_db_compressed)

    # removing the updateStatus file
    os.remove(updateStatus)
  
  

if __name__ == '__main__':
    main()
