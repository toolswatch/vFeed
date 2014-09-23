import sqlite3
from . import config

'''
stats.py -  vfeed.db class for statistics

'''
class vFeedStats(object):

    def __init__(self):

        self.configData = config.database['primary'] 
        self.vfeed_db  = self.configData['vfeed_db']
        self.conn = sqlite3.connect(self.vfeed_db)
        self.cur = self.conn.cursor()
        

    def get_stats(self):


        print"---------------------------------------------------------------"
        print "vFeed.db Statistics"
        print "Distinct values of CVEs and associated third party references"
 
        self.cur.execute("SELECT * from stat_vfeed_kpi; ") 
        
        for self.data in self.cur.fetchall():
            print 'Database build (latest update date):', str(self.data[0])
            print"---------------------------------------------------------------"
            print ""            
            print '[+] Vulnerability Information and References'
            print '\t[-] Common Vulnerability Enumeration (CVE):', self.data[1]
            print '\t[-] Affected Products or Common Platform Enumeration (CPE):', self.data[2]
            print '\t[-] Common Weakness Enumeration (CWE) types:', self.data[3]
            print '\t[-] Common Attack Pattern Enumeration and Classification (CAPEC) types:', self.data[4]
            print '\t[-] SecurityFocus BID:', self.data[5]
            print '\t[-] OSVDB - Open Source Vulnerability Database advisories:', self.data[6]
            print '\t[-] CERT.org Vulnerability Notes:', self.data[7]
            print '\t[-] DOD-CERT Information Assurance Vulnerability Alert (IAVA):', self.data[8]
            print '\t[-] Scip AG Security Advisories:', self.data[9]

            print '\n[+] Third Party Vendors Patches and Advisories'
            print '\t[-] IBM AIX APARs Patches Advisories:', self.data[10]
            print '\t[-] Suse Patches Advisories:', self.data[11]
            print '\t[-] Ubuntu Patches Advisories:', self.data[12]
            print '\t[-] VMware Patches Advisories:', self.data[13]
            print '\t[-] Cisco Patches Advisories:', self.data[14]
            print '\t[-] Debian Patches Advisories:', self.data[15]
            print '\t[-] Fedora Patches Advisories:', self.data[16]
            print '\t[-] Gentoo Patches Advisories:', self.data[17]
            print '\t[-] HP (Hewlett Packard) Patches Advisories:', self.data[18]
            print '\t[-] Mandriva Patches Advisories:', self.data[19]
            print '\t[-] Microsoft Bulletins Advisories:', self.data[20]
            print '\t[-] Microsoft KB Advisories:', self.data[21]
            print '\t[-] Redhat Patches Advisories:', self.data[22]
            print '\t[-] Redhat Bugzilla Advisories:', self.data[23]
            
            print '\n[+] Exploits and Proof of Concepts'
            print '\t[-] Exploit-DB Proof of Concepts and exploits:', self.data[24]
            print '\t[-] Metasploit Exploits or Modules:', self.data[25]
            print '\t[-] Milw0rm Proof of Concepts and exploits:', self.data[26]
            print '\t[-] Saint Corporation Proof of Concepts and exploits:', self.data[27]
            print '\t[-] D2 Elliot Web Exploitation Framework:', self.data[32]
            
            print '\n[+] Third Party Security Scanners Scripts'
            print '\t[-] Nessus Security Scripts:', self.data[28]
            print '\t[-] OpenVAS Security Scripts:', self.data[29]
            print '\t[-] Nmap NSE scripts:', self.data[32]
            print '\t[-] Open Vulnerability Assessment Language (OVAL) definitions:', self.data[30]
 
            print '\n[+] Open Source Intrusion Detection Rules'
            print '\t[-] Snort Detection Rules:', self.data[31]
            print '\t[-] Suricata Detection Rules:', self.data[33]


    def get_latest(self):


        print"---------------------------------------------------------------"
        print "vFeed.db Statistics : Latest added CVEs"
        self.cur.execute("SELECT count(DISTINCT new_cve_id) FROM stat_new_cve; ") 
        self.latest_cve = self.cur.fetchone()
        print '%s total added new CVEs' %self.latest_cve[0]
        print"---------------------------------------------------------------"

        self.cur.execute("SELECT * FROM stat_new_cve; ")
        for self.data in self.cur.fetchall():
            print self.data[0]
            # if you want to display also the CVE summary, just replace with print self.data[0], self.data[1] 