import sys
import sqlite3
import re
from . import config
from . import vFeed

'''
search.py - class to search for CVE or CPE occurrences and return useful information.

'''

class vFeedSearch(object):
    '''
    Main beta version class to search for CVEs and CPEs    
    '''
    def __init__(self,myquery):
                        
        self.configData = config.database['primary']
        self.vfeed_db  = self.configData['vfeed_db']
        self.myquery = myquery
  
    def _db_init(self):

        try:
            self.conn = sqlite3.connect(self.vfeed_db)
            self.cur = self.conn.cursor()
            self.query = (self.cpeid,)
            return (self.cur, self.query)
        except Exception, e:
            print '[error] something occurred while opening the database', self.vfeed_db
            print '[exception]:', e
            exit(0)
  
            
    def search(self):
        
        if 'CVE-' in self.myquery or 'cve-' in self.myquery:
            self._queryCVE()
            exit(0)
    
        if 'CPE:' in self.myquery or 'cpe:' in self.myquery:
            self._queryCPE()
            exit(0)
        else:
            print termc.red + '[Warning] Search free text will be implemented soon.' + termc.end
        
    def _queryCPE(self):
        '''
        Function to query for CPE information. This function will evolve into a more advanced CPEapi class.
        '''
        self.cpeid = self.myquery.lower()
        self._db_init()
        print ''
        print '[+] Querying information for %s ...' % self.cpeid
        
        # Getting Total number of found occurrences 
        self.cur.execute("SELECT count(distinct cveid) from cve_cpe where cpeid like ?", ('%'+self.cpeid+'%',))
        self.count_cve= self.cur.fetchone()
        self.cur.execute("SELECT count(distinct cpeid) from cve_cpe where cpeid like ?", ('%'+self.cpeid+'%',))
        self.count_cpe = self.cur.fetchone()
        
        print '\t [-] Total Unique CVEs        [%s] ' % self.count_cve        
        print '\t [-] Total Found CPEs         [%s] ' % self.count_cpe
        
        if self.count_cve[0] == 0:
            print '[+] Nothing found in the database'
            exit(0)
    
        # Gathering information
        print '[+] Gathering information ... '
        self.cur.execute("SELECT distinct cpeid from cve_cpe where cpeid like ? ORDER BY cpeid DESC", ('%'+self.cpeid+'%',))
        self.cpe_datas = self.cur.fetchall()

        for i in range(0, self.count_cpe[0]):
            self.mycpe = self.cpe_datas[i][0]
            print termc.orange +'\t[-] %s' %self.mycpe+ termc.end
            self.cur.execute("SELECT cveid from cve_cpe where cpeid='%s'" % self.mycpe)
            self.cve_datas = self.cur.fetchall()
            
            for self.cve_data in self.cve_datas:
                self.mycve = self.cve_data[0]
                
                #Loading methods. You can add any other method you wish. Refer to documentation
                
                self.vfeed = vFeed(self.mycve)
                self.cve_info = self.vfeed.get_cve()
                self.cvss_score = self.vfeed.get_cvss()
                self.msf_exploits = self.vfeed.get_msf()
                self.edb_exploits = self.vfeed.get_edb()
                
                #displaying relevant information
                
                print termc.blue +'\t\t[-] %s | CVSS Base :%s' %(self.mycve, self.cvss_score['base']) + termc.end
                self.excerpt_summary  = ' '.join(self.cve_info['summary'].split(' ')[0:7]) + ' ....'    
                print '\t\t\t[->] %s' % self.excerpt_summary 
                
                if len(self.msf_exploits) > 0:
                    print termc.red + '\t\t\t[!] %s Metasploit Exploit(s) Found' %len(self.msf_exploits) + termc.end
        
                if len(self.edb_exploits) > 0:
                    print termc.red + '\t\t\t[!] %s Exploit DB sploits Found' %len(self.edb_exploits) + termc.end      

  
    def _queryCVE(self):
        '''
        Function to query for CVE. This function will be deprecated very soon. Better use get_cve method.
        '''
        
        self.cveid = self.myquery.upper()         
        self.vfeed = vFeed(self.cveid)
        
        print ''
        print '[+] Querying information for %s ...' % self.cveid
        
        if self.vfeed:
            #Loading methods. You can add any other method you wish. Refer to documentation
            
            self.cve_info = self.vfeed.get_cve()
            self.msf_exploits = self.vfeed.get_msf()
            self.edb_exploits = self.vfeed.get_edb()
            print termc.blue + '\t[-] %s' %self.cve_info['summary'] + termc.end
            if len(self.msf_exploits) > 0:
                print termc.red + '\t[!] %s Metasploit Exploit(s) Found' %len(self.msf_exploits) + termc.end        
                
            if len(self.edb_exploits) > 0:
                print termc.red + '\t[!] %s Exploit DB sploits Found' %len(self.edb_exploits) + termc.end 
        
            print '\n[INFO] Try vfeedcli.py export %s for more information !!' % self.cveid

class termc:
  '''
  very basic class for terminal colors.   
  '''
  header = '\033[95m'
  blue = '\033[94m'
  orange = '\033[93m'
  red = '\033[91m'
  end = '\033[0m'
  