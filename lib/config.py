#!/usr/bin/env python


'''
config.py -  Configuration File

#NJ OUCHN

'''

author =   {
            '__name__' : 'NJ OUCHN @toolswatch',
            '__email__' : 'hacker@toolswatch.org',
            '__website__' : 'http://www.toolswatch.org/vfeed',
            }

product =  {
            '__title__' : 'vFeed - Open Source Correlated Local Vulnerability Database',
            '__website__' : 'http://www.toolswatch.org/vfeed',
            '__github__' : 'https://github.com/toolswatch/vFeed',
            '__build__' : 'beta 0.3',
            }


database = {
            'default': 'primary',
            'vfeed_db' : 'vfeed.db',
            
            'primary' : {
                           'description' : 'primary repository',
                           'url' : 'http://www.toolswatch.org/vfeed/',
                           'vfeed_db' : 'vfeed.db',
                           'vfeed_db_compressed' : 'vfeed.db.tgz',
                           'updateStatus' : 'update.dat',  
                        },


            'secondary' : {
                           'descripion' : 'secondary repository',
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

                }    
    


