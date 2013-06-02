#!/usr/bin/env python



import sys
import os
from time import gmtime, strftime
import sqlite3
from xml.etree import ElementTree
from xml.etree.ElementTree import Element, SubElement, Comment, tostring
import xml.dom.minidom
from xml.dom import minidom
import config as config


'''
vFeedApi.py -  vFeed Open Source Vulnerability Database Cross-Linker and Aggregator for NVD/CVE

Class vFeedInfo : supplying the vFeed information
Class vFeed : the main class with 15 methods

'''

class vFeedInfo():
    def __init__(self):
        self.vFeedInfo = {}
    
    
    def get_version(self):
        self.vFeedInfo['title'] = config.product['__title__'] 
        self.vFeedInfo['build'] = config.product['__build__']
        return self.vFeedInfo

    def get_owner(self):

        self.vFeedInfo['author'] = config.author['__name__']
        self.vFeedInfo['email'] = config.author['__email__']
        self.vFeedInfo['website'] = config.author['__website__']
        return self.vFeedInfo

    def get_config(self):

        self.vFeedInfo['primary'] = config.database['primary']
        self.vFeedInfo['secondary'] = config.database['secondary']
        return self.vFeedInfo


class vFeed():

    def __init__(self,cveID):
        
        self.vfeed_db = config.database['vfeed_db']
        self.vfeed_db_url = config.database['primary']['url']
        self.oval_url = config.gbVariables['oval_url']
        self.edb_url = config.gbVariables['edb_url']
        self.cve_url = config.gbVariables['cve_url']
        
        self.cveID = cveID.upper()
        self._check_env(self.vfeed_db)
        self._db_init()
        self._vrfy_cve()
        
        
    def _vrfy_cve(self):
        try:
            self.cur.execute('SELECT * FROM nvd_db WHERE cveid=?', self.query) 
            self.data = self.cur.fetchone()
            if self.data is None:
                print '[warning] Entry %s missed from vFeed Database' %self.cveID
        except Exception, e:
             print '[exception]:', e
             exit(0)

        return self.data
    
    def _check_env(self,file):
        
        if not os.path.isfile(file):
            print '[error] ' + file + ' is missing.'
            print '[db_error] use the "updater.py" to retrieve a fresh copy of the database %s' %self.vfeed_db_url
            exit(0)
        
   
    def _db_init(self):
        
        try:
            self.conn = sqlite3.connect(self.vfeed_db)
            self.cur = self.conn.cursor()
            self.query = (self.cveID,)
            return (self.cur,self.query)
        except Exception, e:
            print '[error] something occurred while opening the database' , self.vfeed_db
            print '[exception]:', e
            exit(0)
    

    def checkCVE(self):
        '''
            CVE verification and basic information extraction
            Returning : dictionary of data (published, modified, description)
        '''
    
        self.cveInfo = {}

        if self.data:
            self.cveInfo['cveDescription'] = str(self.data[3])
            self.cveInfo['publishedDate'] = str(self.data[1])
            self.cveInfo['modifiedDate'] = str(self.data[2])
            
        return self.cveInfo
    
    def checkCVSS(self):
        '''
            CVSS scores extraction
            Returning : dictionary Base, Impact and  Exploit Scores
        '''

        self.cvssScore = {}

        if self.data:
            self.cvssScore['base'] = str(self.data[4])
            self.cvssScore['impact'] = str(self.data[5])
            self.cvssScore['exploit'] = str(self.data[6])
        
        return self.cvssScore

    def checkREF(self):
        '''
        Returning:  CVE references links and their IDs as dictionay
        '''
        self.cnt = 0
        self.cveReferences = {}

        self.cur.execute('SELECT * FROM cve_reference WHERE cveid=?', self.query)

        for self.data in self.cur.fetchall():
            self.cveReferences[self.cnt] = {
                                    'id' : str(self.data[0]),
                                    'link' : str(self.data[1]),
                                    }
            self.cnt+=1
        return self.cveReferences
    
    def checkCWE(self):
        '''
        Returning:  CWE references as dictionary  
        '''
        self.cnt = 0
        self.CWE_id = {}
        self.cur.execute('SELECT * FROM cve_cwe WHERE cveid=?', self.query)

        for self.data in self.cur.fetchall():
            self.CWE_id[self.cnt] = {
                                    'id' : str(self.data[0]),
                                    }
            self.cnt+=1
        
        return self.CWE_id   
    
    def checkCPE(self):
        '''
        Returning:  CPE references as dictionary  
        '''
        self.cnt = 0
        self.CPE_id = {}
        self.cur.execute('SELECT * FROM cve_cpe WHERE cveid=?', self.query)

        for self.data in self.cur.fetchall():
            self.CPE_id[self.cnt] = {
                                    'id' : str(self.data[0]),
                                    }
            self.cnt+=1
        
        return self.CPE_id  


    def checkMS(self):
        '''
        Returning:  Microsoft Patch references as dictionary  
        '''
        self.cnt = 0
        self.MS_id = {}
        self.cur.execute('SELECT * FROM map_cve_ms WHERE cveid=?', self.query)

        for self.data in self.cur.fetchall():
            self.MS_id[self.cnt] = {
                                    'id' : str(self.data[0]),
                                    }
            self.cnt+=1
        
        return self.MS_id  

    def checkKB(self):
        '''
        Returning:  Microsoft KB bulletins as dictionary  
        '''
        self.cnt = 0
        self.KB_id = {}
        self.cur.execute('SELECT * FROM map_cve_mskb WHERE cveid=?', self.query)

        for self.data in self.cur.fetchall():
            self.KB_id[self.cnt] = {
                                    'id' : str(self.data[0]),
                                    }
            self.cnt+=1
        
        return self.KB_id  

    def checkAIXAPAR(self):
        '''
        Returning:  IBM AIX APAR as dictionary  
        '''
        self.cnt = 0
        self.AIXAPAR_id = {}
        self.cur.execute('SELECT * FROM map_cve_aixapar WHERE cveid=?', self.query)

        for self.data in self.cur.fetchall():
            self.AIXAPAR_id[self.cnt] = {
                                    'id' : str(self.data[0]),
                                    }
            self.cnt+=1
        
        return self.AIXAPAR_id  


    def checkREDHAT(self):
        '''
        Returning:  Redhat IDs as dictionary  
        '''
        self.cnt = 0
        self.REDHAT_id = {}
        self.cur.execute('SELECT * FROM map_cve_redhat WHERE cveid=?', self.query)

        for self.data in self.cur.fetchall():
            self.REDHAT_id[self.cnt] = {
                                    'id' : str(self.data[0]),
                                    }
            self.cnt+=1
        
        return self.REDHAT_id 


    def checkSUSE(self):
        '''
        Returning:  SUSE IDs as dictionary  
        '''
        self.cnt = 0
        self.SUSE_id = {}
        self.cur.execute('SELECT * FROM map_cve_suse WHERE cveid=?', self.query)

        for self.data in self.cur.fetchall():
            self.SUSE_id[self.cnt] = {
                                    'id' : str(self.data[0]),
                                    }
            self.cnt+=1
        
        return self.SUSE_id 

    def checkOVAL(self):
        '''
        Returning:  OVAL references file and their IDs as dictionay
        '''
        self.cnt = 0
        self.OVAL_id = {}

        self.cur.execute('SELECT * FROM map_cve_oval WHERE cveid=?', self.query)

        for self.data in self.cur.fetchall():
            self.OVAL_id[self.cnt] = {
                                    'id' : str(self.data[0]),
                                    'file' : self.oval_url + str(self.data[0]),
                                    }
            self.cnt+=1
        return self.OVAL_id  

    def checkNESSUS(self):
        '''
        Returning:  Nessus id, Script Name, Family Script, File Scripts as dictionay
        '''
        self.cnt = 0
        self.NESSUS_id = {}

        self.cur.execute('SELECT * FROM map_cve_nessus WHERE cveid=?', self.query)

        for self.data in self.cur.fetchall():
            self.NESSUS_id[self.cnt] = {
                                    'id' : str(self.data[0]),
                                    'file' : str(self.data[1]),
                                    'name' : str(self.data[2]),
                                    'family' : str(self.data[3]),
                                    }
            self.cnt+=1
        return self.NESSUS_id  

    def checkEDB(self):
        '''
        Returning:  ExploitDB ids and exploit file link
        '''
        self.cnt = 0
        self.EDB_id = {}

        self.cur.execute('SELECT * FROM map_cve_exploitdb WHERE cveid=?', self.query)

        for self.data in self.cur.fetchall():
            self.EDB_id[self.cnt] = {
                                    'id' : str(self.data[0]),
                                    'file' : self.edb_url + str(self.data[0]),
                                    }
            self.cnt+=1
        return self.EDB_id  

    def checkRISK(self):
        '''
        Returning:  Severity Level, Highest Severity Level and PCI Status
        topVulnerable means cvssBase=cvssImpact=cvssExploit =  10
        '''
        
        self.Risk = {}
        self.isTopVulnerable = False
        self.PCIstatus = "Passed"
        
        cve_entry = self._vrfy_cve()
        self.cvssScore = self.checkCVSS()
                    
        if cve_entry is None or 'base' not in self.cvssScore:
            self.levelSeverity = "Unknown"
            self.PCIstatus = "Unknown"
        elif 'impact' in self.cvssScore and 'exploit' in self.cvssScore and self.cvssScore['base'] == "10.0" and self.cvssScore['impact'] == "10.0" and self.cvssScore['exploit'] == "10.0":
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

        self.Risk ={ 'severitylevel' : self.levelSeverity,
                     'topvulnerable' : self.isTopVulnerable,
                     'pciCompliance' : self.PCIstatus,
                    }

        return self.Risk 

########  the exportXML should be removed to a separate class for the next version ########

    def exportXML(self):
        '''
        Produce the vFeed XML format
        The XML file is the flagship feature of the vFeed Concept
        
        '''
        
        self.cveInfo = self.checkCVE()
        self.cveRef = self.checkREF()
        self.CPE_id = self.checkCPE()
        self.CWE_id = self.checkCWE()
        self.Risk= self.checkRISK()
        self.cvssScore = self.checkCVSS()
        self.MS_id = self.checkMS()
        self.KB_id = self.checkKB()
        self.AIXAPAR_id = self.checkAIXAPAR()
        self.REDHAT_id =  self.checkREDHAT()
        self.SUSE_id = self.checkSUSE()
        self.OVAL_id = self.checkOVAL()
        self.NESSUS_id = self.checkNESSUS()
        self.EDB_id = self.checkEDB()
        
        # define id
        self.vfeedid = self.cveID.replace('self.cveID','vFeed')
        self.vfeedfile= self.cveID.replace('-','_') +'.xml'
    
        # define generation time
        self.generated_on = strftime("%a, %d %b %Y %H:%M:%S", gmtime())
    
        # define the vFeed XML attributes
        self.root = Element('vFeed')
        self.root.set('xmlns:xsi', "http://www.w3.org/2001/XMLSchema-instance")
        self.root.set('xmlns:meta', "http://vfeed.toolswatch.org/0.1")
        self.root.set('xmlns', "http://vfeed.toolswatch.org/0.1")
        self.root.set('xsi:schemaLocation', "http://vfeed.toolswatch.org/0.1 http://vfeed.toolswatch.org/vfeed.xsd")
                
        self.root.append(Comment('#####################################'))
        self.root.append(Comment(config.product['__title__']))
        self.root.append(Comment('Generated by vFeedApi.py'))
            
        self.head = SubElement(self.root, 'release')
        self.project_name = SubElement(self.head, 'name')
        self.project_name.text = 'vFeed XML for %s' %self.cveID
        
        self.project_version = SubElement(self.head, 'version')
        self.project_version.text = config.product['__build__']
        
        self.project_author = SubElement(self.head, 'author')
        self.project_author.text = config.author['__name__']
        
        self.project_url = SubElement(self.head, 'url')
        self.project_url.text = config.author['__website__']
        
        self.date_generated = SubElement(self.head, 'date_generated')
        self.date_generated.text = self.generated_on
    
        # Exporting  Vulnerability Summary
        
        self.root.append(Comment('#####################################'))
        self.root.append(Comment('Entry ID'))
        self.entry_head = SubElement(self.root, 'entry',
                        {'exported':self.vfeedfile,
                          'id': self.vfeedid,
                        })
                
        self.vul_summary_date  = SubElement(self.entry_head, 'date',
                                {'published' : self.cveInfo['publishedDate'],
                                 'modified': self.cveInfo['modifiedDate'],
                                })
                
        self.vul_summary = SubElement(self.entry_head, 'summary')
        self.vul_summary.text = self.cveInfo['cveDescription']
        self.vul_summary_ref = SubElement(self.entry_head, 'cve_ref')
        self.vul_summary_ref.text = self.cve_url + self.cveID
    
        # Exporting references
        
        self.entry_head.append(Comment('#####################################'))
        self.entry_head.append(Comment('The Vulnerability References'))
        self.references_head = SubElement(self.entry_head, 'references')
        
        for i in range(0,len(self.cveRef)):
            self.source_head  = SubElement(self.references_head, 'source',
                            {'reference': self.cveRef[i]['link'],
                              'id': self.cveRef[i]['id'],
                            })
        
        # Exporting Targets CPEs ids
                
        if self.CPE_id:
            self.entry_head.append(Comment('#####################################'))
            self.entry_head.append(Comment('Vulnerable Targets according to CPE'))
            self.vulnerabletargets_head = SubElement(self.entry_head, 'vulnerableTargets',
                                            {'totalCPE' : str(len(self.CPE_id)),})
            

            for i in range(0,len(self.CPE_id)):
                self.cpe_head  = SubElement(self.vulnerabletargets_head, 'cpe',
                            {'id':self.CPE_id[i]['id'],
                            })
        
        # Exporting Risk Scoring
    
        self.entry_head.append(Comment('#####################################'))
        self.entry_head.append(Comment('Risk Scoring Evaluation'))
        self.riskscoring_head = SubElement(self.entry_head, 'riskScoring')
                
        self.risk_head  = SubElement(self.riskscoring_head, 'severityLevel',
                        {'status':self.Risk['severitylevel'],
                        })
    
        self.risk_head  = SubElement(self.riskscoring_head, 'cvss',
                        {'cvssvector':'not_defined_yet',
                          'base':self.cvssScore['base'],
                          'impact':self.cvssScore['impact'],
                           'exploit':self.cvssScore['exploit'],
                        })               
     
        self.risk_head  = SubElement(self.riskscoring_head, 'topVulnerable',
                        {'status':str(self.Risk['topvulnerable']),
                        })
    
        self.risk_head  = SubElement(self.riskscoring_head, 'topAlert',
                        {'status':"not_defined_yet",
                         })
        
        self.risk_head  = SubElement(self.riskscoring_head, 'pciCompliance',
                        {'status':self.Risk['pciCompliance'],
                        })    


    # Exporting Patch Management
        
        self.entry_head.append(Comment('#####################################'))
        self.entry_head.append(Comment('Patch Management'))
        self.patchmanagement_head = SubElement(self.entry_head, 'patchManagement')
                
        ## Exporting Microsoft MS Patches
                
        for i in range(0,len(self.MS_id)):        
            self.patch_head  = SubElement(self.patchmanagement_head, 'patch',
                            {'id':self.MS_id[i]['id'],
                            'reference':'microsoft',
                            })
        
        ## Exporting Microsoft KB Patches    
                
        for i in range(0,len(self.KB_id)):
            self.patch_head  = SubElement(self.patchmanagement_head, 'patch',
                            {'id':self.KB_id[i]['id'],
                             'reference':'microsoft KB',
                            })  
                

        ## Exporting IBM AIXAPAR Patches
                
        for i in range(0,len(self.AIXAPAR_id)):        
            self.patch_head  = SubElement(self.patchmanagement_head, 'patch',
                            {'id': self.AIXAPAR_id[i]['id'],
                            'reference':'IBM',
                            })
    
        ## Exporting REDHAT Patches
        
        for i in range(0,len(self.REDHAT_id)):        
            self.patch_head  = SubElement(self.patchmanagement_head, 'patch',
                            {'id': self.REDHAT_id[i]['id'],
                            'reference':'REDHAT',
                            })
    
        ## Exporting SUSE Patches
                
        for i in range(0,len(self.SUSE_id)):        
            self.patch_head  = SubElement(self.patchmanagement_head, 'patch',
                            {'id': self.SUSE_id[i]['id'],
                            'reference':'SUSE',
                            })



        # Attack and Weaknesses Patterns
        
        if self.CWE_id:
            
            self.entry_head.append(Comment('#####################################'))
            self.entry_head.append(Comment('Attack and Weaknesses Categories. Useful when performing classification of threats'))
            self.attackclassification_head = SubElement(self.entry_head, 'attackPattern')
            
            for i in range(0,len(self.CWE_id)):
                self.attackPattern_head  = SubElement(self.attackclassification_head, 'source',
                                        {'standard':'CWE - Common Weakness Enumeration',
                                         'id':self.CWE_id[i]['id'],
                                         'title': "not_implemented_yet"
                                         })


        # Exporting Assessment, security tests and exploitation
         
        self.entry_head.append(Comment('#####################################'))
        self.entry_head.append(Comment('Assessment and security Tests. The IDs and source could be leveraged to test the vulnerability'))
        self.securitytest_head = SubElement(self.entry_head, 'assessment')
      
        ## Exporting OVAL ids    
        for i in range(0,len(self.OVAL_id)):
            self.ovalChecks_head  = SubElement(self.securitytest_head, 'check',
                                      {'type':'Local Security Testing',
                                       'id': self.OVAL_id[i]['id'],
                                       'utility': "OVAL Interpreter",
                                       'file' : self.OVAL_id[i]['file'],
                                       })        
         
        ## Exporting Nessus attributes         
        for i in range(0,len(self.NESSUS_id)):
            self.nessusChecks_head  = SubElement(self.securitytest_head, 'check',
                                     {'type':'Remote Security Testing',
                                      'id': self.NESSUS_id[i]['id'],
                                      'name': self.NESSUS_id[i]['name'],
                                      'family': self.NESSUS_id[i]['family'],
                                      'file' : self.NESSUS_id[i]['file'],
                                      'utility': "Nessus Vulnerability Scanner",
                                      })     
        ## Exporting EDB ids 
        for i in range(0,len(self.EDB_id)):
            self.exploitChecks_head  = SubElement(self.securitytest_head, 'check',
                                     {'type':'Exploitation',
                                      'utility':"exploit-db",
                                      'id': self.EDB_id[i]['id'],
                                      'file' :  self.EDB_id[i]['file'],
                                      }) 


        self.xmlfile=open(self.vfeedfile, 'w+')
        #print self.prettify(self.root)
        print '[info] vFeed xml file %s exported for %s' %(self.vfeedfile,self.cveID)
        print >> self.xmlfile,self.prettify(self.root)
    
    
    def prettify(self,elem):
        """Return a pretty-printed XML string for the Element.
        This function found on internet.
        So thanks to its author whenever he is.
        """
        rough_string = ElementTree.tostring(elem, 'UTF-8')
        reparsed = minidom.parseString(rough_string)
        return reparsed.toprettyxml(indent="  ")
