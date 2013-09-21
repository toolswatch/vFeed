'''
vFeed Framework - The Open Source Cross Linked Local Vulnerability Database

Name : config.py -  Configuration File
Purpose : Configuration File. Handles global variables and database URLs.
'''

author = {
    '__name__': 'NJ OUCHN @toolswatch',
    '__email__': 'hacker@toolswatch.org',
    '__website__': 'https://github.com/toolswatch/vFeed',
}


product = {
    '__title__': 'vFeed - Open Source Cross-linked and Aggregated Local Vulnerability Database',
    '__website__': 'http://www.toolswatch.org/vfeed',
    '__mainRepository__': 'https://github.com/toolswatch/vFeed',
    '__build__': 'beta 0.4.5',
}


database = {
    'default': 'primary',
    'vfeed_db': 'vfeed.db',

    'primary': {
        'description': 'primary repository',
        'url': 'http://www.toolswatch.org/vfeed/',
        'vfeed_db': 'vfeed.db',
        'vfeed_db_compressed': 'vfeed.db.tgz',
        'updateStatus': 'update.dat',
    },


    'secondary': {
        'description': 'secondary repository (not effective yet)',
        'url': 'http://www.vfeed.org/',
        'vfeed_db': 'vfeed.db',
        'vfeed_db_compressed': 'vfeed.db.tgz',
        'updateStatus': 'update.dat',
    },

}

gbVariables = {
    'cve_url': 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=',
    'certvn_url':'http://www.kb.cert.org/vuls/id/',
    'edb_url': 'http://www.exploit-db.com/exploits/',
    'oval_url': 'http://oval.mitre.org/repository/data/getDef?id=',
    'redhat_oval_url': 'https://www.redhat.com/security/data/oval/com.redhat.rhsa-',
    'cwe_url' : 'http://cwe.mitre.org/data/definitions/',
    'capec_url' : 'http://capec.mitre.org/data/definitions/',
    'scip_url'  : 'http://www.scip.ch/?vuldb',
    'osvdb_url'  : 'http://www.osvdb.org/show/osvdb/',
    'milw0rm_url' : 'http://www.milw0rm.com/exploits/',
    'ms_bulletin_url' : 'http://technet.microsoft.com/en-us/security/bulletin/',    
    'ms_kb_url' : 'http://support.microsoft.com/default.aspx?scid=kb;en-us;',
}
