#!/usr/bin/env python


'''
vFeed Framework - The Open Source Cross Linked Local Vulnerability Database

Name : config.py -  Configuration File
Purpose : Configuration File. Handles globale variables and database URLs.
'''

author =   {
            '__name__' : 'NJ OUCHN @toolswatch',
            '__email__' : 'hacker@toolswatch.org',
            '__website__' : 'http://www.toolswatch.org/vfeed',
            }

product =  {
            '__title__' : 'vFeed - Open Source Correlated Local Vulnerability Database',
            '__website__' : 'http://www.toolswatch.org/vfeed',
            '__mainRepository__' : 'https://github.com/toolswatch/vFeed',
            '__build__' : 'beta 0.3.5',
            }


database = {
            'default': 'primary',
            'vfeed_db' : 'vfeed.db',
            
            'primary' : {
                           'description' : 'primary repository',
                           'url' : 'http://www.toolswatch.org/vfeed/',
                           'vfeed_db' : 'vfeed.db',
                           'vfeed_db_compressed' : 'vfeed.db.tgz',
                           'updateStatus' : 'update.txt',  
                        },


            'secondary' : {
                           'descripion' : 'secondary repository (not effective yet)',
                           'url' : 'http://www.vfeed.org/',
                           'vfeed_db' : 'vfeed.db',
                           'vfeed_db_compressed' : 'vfeed.db.tgz',
                           'updateStatus' : 'update.dat', 
                        },

            }

gbVariables = {
                'cve_url' : 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=',
                'edb_url' : 'http://www.exploit-db.com/exploits/',
                'oval_url' : 'http://oval.mitre.org/repository/data/getDef?id=',
                'redhat_oval_url' : 'https://www.redhat.com/security/data/oval/com.redhat.rhsa-'

                }    
    


