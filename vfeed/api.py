import os
import sqlite3

from . import config

'''
api.py -  vFeed - Open Source Cross-linked and Aggregated Local Vulnerability Database

'''
class vFeed(object):

    def __init__(self, cveID):

        self.vfeed_db = config.database['vfeed_db']
        self.vfeed_db_url = config.database['primary']['url']
        self.oval_url = config.gbVariables['oval_url']
        self.edb_url = config.gbVariables['edb_url']
        
        self.cveID = cveID.upper()
        self._check_env(self.vfeed_db)
        self._db_init()
        self._vrfy_cve()

    def _vrfy_cve(self):
        try:
            self.cur.execute('SELECT * FROM nvd_db WHERE cveid=?', self.query)
            self.data = self.cur.fetchone()
            if self.data is None:
                print '[warning] Entry %s is missed from vFeed Database' % self.cveID
                print '[hint] Update your local vfeed.db'
                exit(0)
        except Exception, e:
            print '[exception]:', e
            exit(0)

        return self.data

    def _check_env(self, file):

        if not os.path.isfile(file):
            print '[error] ' + file + ' is missing.'
            print '[db_error] use the "vfeed_update.py" to retrieve a fresh copy of the database %s' % self.vfeed_db_url
            exit(0)

    def _db_init(self):

        try:
            self.conn = sqlite3.connect(self.vfeed_db)
            self.cur = self.conn.cursor()
            self.query = (self.cveID,)
            return (self.cur, self.query)
        except Exception, e:
            print '[error] something occurred while opening the database', self.vfeed_db
            print '[exception]:', e
            exit(0)

    def get_cve(self):
        '''
            CVE verification and basic information extraction
            Returning : dictionary of data (published, modified, description)
        '''

        self.cveInfo = {}

        if self.data:
            self.cveInfo['summary'] = str(self.data[3])
            self.cveInfo['published'] = str(self.data[1])
            self.cveInfo['modified'] = str(self.data[2])

        return self.cveInfo

    def get_cvss(self):
        '''
            CVSS scores extraction
            Returning : dictionary Base, Impact and  Exploit Scores
        '''
        self._vrfy_cve()
        self.cvssScore = {}

        if self.data:
            self.cvssScore['base'] = str(self.data[4])
            self.cvssScore['impact'] = str(self.data[5])
            self.cvssScore['exploit'] = str(self.data[6])
            self.cvssScore['access_vector'] = str(self.data[7])
            self.cvssScore['access_complexity'] = str(self.data[8])
            self.cvssScore['authentication'] = str(self.data[9])      
            self.cvssScore['confidentiality_impact'] = str(self.data[10])
            self.cvssScore['integrity_impact'] = str(self.data[11])
            self.cvssScore['availability_impact'] = str(self.data[12])

        return self.cvssScore

    def get_refs(self):
        '''
        Returning:  CVE references links and their IDs as dictionay
        '''
        self.cnt = 0
        self.cveReferences = {}
        self.cur.execute(
            'SELECT * FROM cve_reference WHERE cveid=?', self.query)

        for self.data in self.cur.fetchall():
            self.cveReferences[self.cnt] = {
                'id': str(self.data[0]),
                'link': str(self.data[1]),
            }
            self.cnt += 1
        return self.cveReferences

    def get_osvdb(self):
        '''
        Returning:  OSVDB (Open Sourced Vulnerability Database) ids as dictionay
        http://www.osvdb.org/
        '''
        self.cnt = 0
        self.OSVDB_id = {}
        self.cur.execute(
            'SELECT * FROM map_cve_osvdb WHERE cveid=?', self.query)

        for self.data in self.cur.fetchall():
            self.OSVDB_id[self.cnt] = {
                'id': str(self.data[0]),
            }
            self.cnt += 1
        return self.OSVDB_id        
    
    def get_scip(self):
        '''
        Returning:  SCIP ids and links as dictionay
        http://www.scip.ch
        '''
        self.cnt = 0
        self.SCIP_id = {}
        self.cur.execute(
            'SELECT * FROM map_cve_scip WHERE cveid=?', self.query)

        for self.data in self.cur.fetchall():
            self.SCIP_id[self.cnt] = {
                'id': str(self.data[0]),
                'link': str(self.data[1]),
            }
            self.cnt += 1
        return self.SCIP_id    

    def get_certvn(self):
        '''
        Returning:  CERT VU ids and links as dictionay
        http://www.cert.org/kb/
        '''
        self.cnt = 0
        self.CERTVN_id = {}
        self.cur.execute(
            'SELECT * FROM map_cve_certvn WHERE cveid=?', self.query)

        for self.data in self.cur.fetchall():
            self.CERTVN_id[self.cnt] = {
                'id': str(self.data[0]),
                'link': str(self.data[1]),
            }
            self.cnt += 1
        return self.CERTVN_id    


    def get_scip(self):
        '''
        Returning:  SCIP ids and links as dictionay
        http://www.scip.ch
        '''
        self.cnt = 0
        self.SCIP_id = {}
        self.cur.execute(
            'SELECT * FROM map_cve_scip WHERE cveid=?', self.query)

        for self.data in self.cur.fetchall():
            self.SCIP_id[self.cnt] = {
                'id': str(self.data[0]),
                'link': str(self.data[1]),
            }
            self.cnt += 1
        return self.SCIP_id  


    def get_iavm(self):
        '''
        Returning:  IAVM Ids, DISA keys and title as dictionay
        IAVM stands for Information Assurance Vulnerability Management
        http://www.prim.osd.mil/cap/iavm_req.html?p=1.1.1.1.3
        '''
        self.cnt = 0
        self.IAVM_id = {}
        self.cur.execute(
            'SELECT * FROM map_cve_iavm WHERE cveid=?', self.query)

        for self.data in self.cur.fetchall():
            self.IAVM_id[self.cnt] = {
                'id': str(self.data[0]),
                'key': str(self.data[1]),
                'title': str(self.data[2]),
            }
            self.cnt += 1
        return self.IAVM_id   

    def get_cwe(self):
        '''
        Returning:  CWE references as dictionary
        '''
        self.cnt = 0
        self.cnt2 = 0
        self.CWE_id = {}
        
        self.cur.execute('SELECT * FROM cve_cwe WHERE cveid=?', self.query)
        
        
        for self.data in self.cur.fetchall():
            self.cwe_id = str(self.data[0])
            self.query2 = (self.cwe_id,)
            self.cur.execute('SELECT * FROM cwe_db WHERE cweid=?', self.query2)
                        
            for self.data2 in self.cur.fetchall():
                self.CWE_id[self.cnt] = {
                   'id': self.cwe_id,
                   'title' : str(self.data2[1]),
                }

            self.cnt += 1

        return self.CWE_id

    def get_capec(self):
        '''
        Returning:  CAPEC references as dictionary
        '''
        
        self.cnt = 0
        self.CWE_id = self.get_cwe()
        self.CAPEC_id = {}
        
        if self.CWE_id:
            for i in range(0, len(self.CWE_id)):
                self.query2 = (self.CWE_id[i]['id'],)
                self.cur.execute('SELECT * FROM cwe_capec WHERE cweid=?', self.query2)
                
                for self.data2 in self.cur.fetchall():                    
                    self.cwe_id = self.CWE_id[i]['id']
                    
                    self.CAPEC_id[self.cnt] = {
                       'cwe' : self.cwe_id,
                       'id': str(self.data2[0]),
                    }
                    
                    self.cnt += 1
        
        return self.CAPEC_id


    def get_category(self):
        '''
        Returning:  CWE Weakness Categories (as Top 2011 ....) references as dictionary
        '''       
        self.cnt = 0
        self.CWE_id = self.get_cwe()
        self.CATEGORY_id = {}
        
        if self.CWE_id:
            for i in range(0, len(self.CWE_id)):
                self.query2 = (self.CWE_id[i]['id'],)
                self.cur.execute('SELECT * FROM cwe_category WHERE cweid=?', self.query2)
                
                for self.data2 in self.cur.fetchall():                                                            
                    self.CATEGORY_id[self.cnt] = {
                       'id' : str(self.data2[0]),
                       'title': str(self.data2[1]),
                    }
                    
                    self.cnt += 1

        return self.CATEGORY_id

    def get_cpe(self):
        '''
        Returning:  CPE references as dictionary
        '''
        self.cnt = 0
        self.CPE_id = {}
        self.cur.execute('SELECT * FROM cve_cpe WHERE cveid=?', self.query)

        for self.data in self.cur.fetchall():
            self.CPE_id[self.cnt] = {
                'id': str(self.data[0]),
            }
            self.cnt += 1

        return self.CPE_id

    def get_ms(self):
        '''
        Returning:  Microsoft Patch references as dictionary
        '''
        self.cnt = 0
        self.MS_id = {}
        self.cur.execute('SELECT * FROM map_cve_ms WHERE cveid=?', self.query)

        for self.data in self.cur.fetchall():
            self.MS_id[self.cnt] = {
                'id': str(self.data[0]),
                'title': str(self.data[1]),
            }
            self.cnt += 1

        return self.MS_id
    

    def get_kb(self):
        '''
        Returning:  Microsoft KB bulletins as dictionary
        '''
        self.cnt = 0
        self.KB_id = {}
        self.cur.execute(
            'SELECT * FROM map_cve_mskb WHERE cveid=?', self.query)

        for self.data in self.cur.fetchall():
            self.KB_id[self.cnt] = {
                'id': str(self.data[0]),
                'title': str(self.data[1]),
            }
            self.cnt += 1

        return self.KB_id

    def get_aixapar(self):
        '''
        Returning:  IBM AIX APAR as dictionary
        '''
        self.cnt = 0
        self.AIXAPAR_id = {}
        self.cur.execute(
            'SELECT * FROM map_cve_aixapar WHERE cveid=?', self.query)

        for self.data in self.cur.fetchall():
            self.AIXAPAR_id[self.cnt] = {
                'id': str(self.data[0]),
            }
            self.cnt += 1

        return self.AIXAPAR_id

    def get_redhat(self):
        '''
        Returning:  Redhat IDs & Bugzilla
        '''
        self.cnt = 0
        self.cnt2 = 0
        self.REDHAT_id = {}
        self.BUGZILLA_id = {}

        self.cur.execute(
            'SELECT * FROM map_cve_redhat WHERE cveid=?', self.query)

        for self.data in self.cur.fetchall():
            self.REDHAT_id[self.cnt] = {
                'id': str(self.data[0]),
                'oval': str(self.data[1]),
                'title': str(self.data[2]),
            }

            # Querying the mapped redhat id and bugzilla id table. New query is set.
            self.query2 = (self.REDHAT_id[self.cnt]['id'],)
            self.cur.execute('SELECT * FROM map_redhat_bugzilla WHERE redhatid=?', self.query2)

            for self.data2 in self.cur.fetchall():
                self.BUGZILLA_id[self.cnt2] = {
                    'date_issue': str(self.data2[0]),
                    'id': str(self.data2[1]),
                    'title': str(self.data2[2]),
                }
                self.cnt2 += 1
            self.cnt += 1

        return (self.REDHAT_id, self.BUGZILLA_id)

    def get_debian(self):
        '''
        Returning:  Debian IDs as dictionary
        '''
        self.cnt = 0
        self.DEBIAN_id = {}
        self.cur.execute(
            'SELECT * FROM map_cve_debian WHERE cveid=?', self.query)

        for self.data in self.cur.fetchall():
            self.DEBIAN_id[self.cnt] = {
                'id': str(self.data[0]),
            }
            self.cnt += 1

        return self.DEBIAN_id

    def get_suse(self):
        '''
        Returning:  SUSE IDs as dictionary
        '''
        self.cnt = 0
        self.SUSE_id = {}
        self.cur.execute(
            'SELECT * FROM map_cve_suse WHERE cveid=?', self.query)

        for self.data in self.cur.fetchall():
            self.SUSE_id[self.cnt] = {
                'id': str(self.data[0]),
            }
            self.cnt += 1

        return self.SUSE_id

    def get_ubuntu(self):
        '''
        Returning:  UBUNTU IDs as dictionary
        '''
        self.cnt = 0
        self.UBUNTU_id = {}
        self.cur.execute(
            'SELECT * FROM map_cve_ubuntu WHERE cveid=?', self.query)

        for self.data in self.cur.fetchall():
            self.UBUNTU_id[self.cnt] = {
                'id': str(self.data[0]),
            }
            self.cnt += 1

        return self.UBUNTU_id

    def get_gentoo(self):
        '''
        Returning:  GENTOO IDs as dictionary
        '''
        self.cnt = 0
        self.GENTOO_id = {}
        self.cur.execute(
            'SELECT * FROM map_cve_gentoo WHERE cveid=?', self.query)

        for self.data in self.cur.fetchall():
            self.GENTOO_id[self.cnt] = {
                'id': str(self.data[0]),
            }
            self.cnt += 1

        return self.GENTOO_id

    def get_fedora(self):
        '''
        Returning:  FEDORA IDs as dictionary
        '''
        self.cnt = 0
        self.FEDORA_id = {}
        self.cur.execute(
            'SELECT * FROM map_cve_fedora WHERE cveid=?', self.query)

        for self.data in self.cur.fetchall():
            self.FEDORA_id[self.cnt] = {
                'id': str(self.data[0]),
            }
            self.cnt += 1

        return self.FEDORA_id

    def get_mandriva(self):
        '''
        Returning:  MANDRIVA IDs as dictionary
        '''
        self.cnt = 0
        self.MANDRIVA_id = {}
        self.cur.execute(
            'SELECT * FROM map_cve_mandriva WHERE cveid=?', self.query)

        for self.data in self.cur.fetchall():
            self.MANDRIVA_id[self.cnt] = {
                'id': str(self.data[0]),
            }
            self.cnt += 1

        return self.MANDRIVA_id

    def get_cisco(self):
        '''
        Returning:  Cisco SA Advisory ids as dictionary
        '''
        self.cnt = 0
        self.CISCO_id = {}
        self.cur.execute('SELECT * FROM map_cve_cisco WHERE cveid=?', self.query)

        for self.data in self.cur.fetchall():
            self.CISCO_id[self.cnt] = {
                'id': str(self.data[0]),
            }
            self.cnt += 1

        return self.CISCO_id


    def get_oval(self):
        '''
        Returning:  OVAL references file and their IDs as dictionay
        '''
        self.cnt = 0
        self.OVAL_id = {}
        self.cur.execute(
            'SELECT * FROM map_cve_oval WHERE cveid=?', self.query)

        for self.data in self.cur.fetchall():
            self.OVAL_id[self.cnt] = {
                'id': str(self.data[0]),
                'file': self.oval_url + str(self.data[0]),
            }
            self.cnt += 1
        return self.OVAL_id

    def get_nessus(self):
        '''
        Returning:  Nessus id, Script Name, Family Script, File Scripts as dictionay
        '''
        self.cnt = 0
        self.NESSUS_id = {}
        self.cur.execute(
            'SELECT * FROM map_cve_nessus WHERE cveid=?', self.query)

        for self.data in self.cur.fetchall():
            self.NESSUS_id[self.cnt] = {
                'id': str(self.data[0]),
                'file': str(self.data[1]),
                'name': str(self.data[2]),
                'family': str(self.data[3]),
            }
            self.cnt += 1
        return self.NESSUS_id

    def get_openvas(self):
        '''
        Returning:  OpenVAS id, Script Name, Family Script, File Scripts as dictionay
        '''
        self.cnt = 0
        self.OPENVAS_id = {}
        self.cur.execute(
            'SELECT * FROM map_cve_openvas WHERE cveid=?', self.query)
         
        for self.data in self.cur.fetchall():
            self.OPENVAS_id[self.cnt] = {
                'id': str(self.data[0]),
                'file': str(self.data[1]),
                'name': str(self.data[2]),
                'family': str(self.data[3]),
            }
            self.cnt += 1
        return self.OPENVAS_id


    def get_edb(self):
        '''
        Returning:  ExploitDB ids and exploit file link
        '''
        self.cnt = 0
        self.EDB_id = {}
        self.cur.execute(
            'SELECT * FROM map_cve_exploitdb WHERE cveid=?', self.query)

        for self.data in self.cur.fetchall():
            self.EDB_id[self.cnt] = {
                'id': str(self.data[0]),
                'file': self.edb_url + str(self.data[0]),
            }
            self.cnt += 1
        return self.EDB_id

    def get_milw0rm(self):
        '''
        Returning:  milw0rm ids
        '''
        self.cnt = 0
        self.MILWORM_id = {}
        self.cur.execute(
            'SELECT * FROM map_cve_milw0rm WHERE cveid=?', self.query)

        for self.data in self.cur.fetchall():
            self.MILWORM_id[self.cnt] = {
                'id': str(self.data[0]),
            }
            self.cnt += 1
        return self.MILWORM_id


    def get_saint(self):
        '''
        Returning:  Saint Corporation Exploits ids and files
        '''
        self.cnt = 0
        self.SAINT_id = {}
        self.cur.execute(
            'SELECT * FROM map_cve_saint WHERE cveid=?', self.query)

        for self.data in self.cur.fetchall():
            self.SAINT_id[self.cnt] = {
                'id': str(self.data[0]),
                'title': str(self.data[1]),
                'file': str(self.data[2]),
            }
            self.cnt += 1

        return self.SAINT_id

    def get_msf(self):
        '''
        Returning:  Metasploit Exploits ids, files link and exploit title
        '''
        self.cnt = 0
        self.MSF_id = {}
        self.cur.execute(
            'SELECT * FROM map_cve_msf WHERE cveid=?', self.query)

        for self.data in self.cur.fetchall():
            self.MSF_id[self.cnt] = {
                'id': str(self.data[0]),
                'file': str(self.data[1]),
                'title': str(self.data[2]),
            }
            self.cnt += 1
        return self.MSF_id


    def get_snort(self):
        '''
        Returning:  Snort references as dictionary
        '''
        self.cnt = 0
        self.SNORT_id = {}
        self.cur.execute('SELECT * FROM map_cve_snort WHERE cveid=?', self.query)
        
        for self.data in self.cur.fetchall():
            self.SNORT_id[self.cnt] = {
                'id': str(self.data[0]),
                'signature': str(self.data[1]),
                'classtype': str(self.data[2]),
            }
            self.cnt += 1

        return self.SNORT_id

        
    def get_risk(self):
        '''
        Returning:  Severity Level, Highest Severity Level, CWE Category (Top 2011, OWASP...) and PCI Status
        topVulnerable means cvssBase=cvssImpact=cvssExploit =  10
        '''

        self.Risk = {}
        self.cvssScore = self.get_cvss()
        self.topAlert = self._isTopAlert()
        self.isTopVulnerable = False
        self.PCIstatus = "Passed"
        cve_entry = self._vrfy_cve()
       
        if cve_entry is None or self.cvssScore['base'] == "not_defined":
            self.levelSeverity = "not_calculated -- Reason: CVSS is not defined"
            self.isTopVulnerable = "not_calculated -- Reason: CVSS is not defined"
            self.PCIstatus = "not_calculated -- Reason: CVSS is not defined"
        elif 'impact' in self.cvssScore and 'exploit' in self.cvssScore\
        and self.cvssScore['base'] == "10.0" and self.cvssScore['impact'] == "10.0"\
        and self.cvssScore['exploit'] == "10.0":
            self.levelSeverity = "High"
            self.isTopVulnerable = True
            self.PCIstatus = "Failed"
        elif self.cvssScore['base'] >= "7.0":
            self.levelSeverity = "High"
            self.PCIstatus = "Failed"
        elif self.cvssScore['base'] >= "4.0" and self.cvssScore['base'] <= "6.9":
            self.levelSeverity = "Moderate"
        elif self.cvssScore['base'] >= "0.1" and self.cvssScore['base'] <= "3.9":
            self.levelSeverity = "Low"
        
        # if a top alert is found then PCI status should be failed.
        if self.topAlert:
            self.PCIstatus = "Failed"        
        
        self.Risk = {'severitylevel': self.levelSeverity,
                     'topvulnerable': self.isTopVulnerable,
                     'pciCompliance': self.PCIstatus,
                     'topAlert' : self.topAlert 
                     }
          
        return self.Risk


    def _isTopAlert(self):
        
        '''
        Returning:  The CWE Category such as CWE/SANS 2011, OWASP 2010....

        '''
        
        self.topAlert = ""
        # get_cwe should be invoked to get the number of CWEs associated with a CVEs. Rare cases where CVE has more than 1 CWE.
        
        self.CWE_id = self.get_cwe()
        self.CATEGORY_id = self.get_category()
        self.TopCategories = ['CWE-929','CWE-930','CWE-931','CWE-932','CWE-933','CWE-934','CWE-935','CWE-936','CWE-937','CWE-938','CWE-810','CWE-811','CWE-812','CWE-813', 'CWE-814', 'CWE-815','CWE-816','CWE-817','CWE-818','CWE-819','CWE-864','CWE-865','CWE-691']

        '''
        CWE-864 --> 2011 Top 25 - Insecure Interaction Between Components
        CWE-865 --> 2011 Top 25 - Risky Resource Management
        CWE-691 --> Insufficient Control Flow Management
        CWE-810 --> OWASP Top Ten 2010 Category A1 - Injection
        CWE-811 --> OWASP Top Ten 2010 Category A2
        CWE-812 --> OWASP Top Ten 2010 Category A3
        CWE-813 --> OWASP Top Ten 2010 Category A4
        CWE-814 --> OWASP Top Ten 2010 Category A5 
        CWE-815 --> OWASP Top Ten 2010 Category A6
        CWE-816 --> OWASP Top Ten 2010 Category A7
        CWE-817 --> OWASP Top Ten 2010 Category A8 
        CWE-818 --> OWASP Top Ten 2010 Category A9
        CWE-819 --> OWASP Top Ten 2010 Category A10
        CWE-929 --> OWASP Top Ten 2013 Category A1 - Injection
        CWE-930 --> OWASP Top Ten 2013 Category A2 - Broken Authentication and Session Management
        CWE-931 --> OWASP Top Ten 2013 Category A3 - Cross-Site Scripting (XSS)
        CWE-932 --> OWASP Top Ten 2013 Category A4 - Insecure Direct Object References
        CWE-933 --> OWASP Top Ten 2013 Category A5 - Security Misconfiguration
        CWE-934 --> OWASP Top Ten 2013 Category A6 - Sensitive Data Exposure
        CWE-935 --> OWASP Top Ten 2013 Category A7 - Missing Function Level Access Control
        CWE-936 --> OWASP Top Ten 2013 Category A8 - Cross-Site Request Forgery (CSRF)
        CWE-937 --> OWASP Top Ten 2013 Category A9 - Using Components with Known Vulnerabilities
        CWE-938 --> OWASP Top Ten 2013 Category A10 - Unvalidated Redirects and Forwards

        
        '''
        
        if self.CATEGORY_id:
            for i in range(len(self.CWE_id), len(self.CATEGORY_id) + len(self.CWE_id) ):
                # Checking for top CWE 2011, OWASP Top Ten 2010 and OWASP Top 2013
                for self.cat_id in self.TopCategories:
                    if self.CATEGORY_id[i]['id'] == self.cat_id:
                        self.topAlert += self.CATEGORY_id[i]['title'] + " | "
                        
        
        return self.topAlert
