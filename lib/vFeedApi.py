#!/usr/bin/env python

__author__ = 'NJ OUCHN'
__email__ = 'hacker@toolswatch.org'
__website__= 'http://www.toolswatch.org/vfeed'
__release__ = 'vFeed b0.2'
 


import sys
import os
from time import gmtime, strftime
import sqlite3
from xml.etree import ElementTree
from xml.etree.ElementTree import Element, SubElement, Comment, tostring
import xml.dom.minidom
from xml.dom import minidom


'''
vFeedApi.py -  vFeed Open Source Vulnerability Database Cross-Linker and Aggregator for NVD/CVE

Available methods :

- checkCVE
- checkCVSS
- checkReferences
- checkCWE
- checkCPE
- checkOVAL
- checkNESSUS
- checkEDB
- checkMS
- checkKB
- checkAIXAPAR
- checkREDHAT
- checkSUSE
- checkRISK
- exportXML

Todo

- add MS/KB url links to patches
- add headers only with returned values.

'''

        
# Global Values initialization
 
edb_url = "http://www.exploit-db.com/exploits/"
oval_url = "http://oval.mitre.org/repository/data/getDef?id="
vfeed_db = 'vfeed.db'
vfeed_db_url = 'http://www.toolswatch.org/vfeed/vfeed.db.tgz'

# Mandatory vFeed DB Test

if not os.path.isfile(vfeed_db):
    print '[error] ' + vfeed_db + ' does not exist. The database is mandatory'
    print '[info] Get manually your copy from %s' %vfeed_db_url
    print '[hint] Start the updater.py to download automatically the database'
    exit(0)


def connDb():
    '''
    vFeed SQLite Database initialization    
    ''' 

    conn = sqlite3.connect(vfeed_db)
    cur = conn.cursor()
    return cur
        

def verifyCVE(myCVE):
    '''
    CVE verification and basic attributes extraction
    Returning : tuple of data (published, modified, description, CVSS scores)
    '''
    global PublishedDate
    global ModifiedDate
    global vulnDescription
    global cvssBase
    global cvssImpact
    global cvssExploit
        
    # Defining the global variables
        
    cur = connDb()
    
    query = (myCVE,)
    cur.execute('SELECT * FROM nvd_db WHERE cveid=?', query) 
    data = cur.fetchone()
    
    if data is None:
        print '[error] Entry %s missed from vFeed Database' %myCVE
        exit(0)
        
    else:

        # Extracting the basic CVE attributes

        PublishedDate = str(data[1])
        ModifiedDate = str(data[2])
        vulnDescription = str(data[3])
        cvssBase =  str(data[4])
        cvssImpact = str(data[5])
        cvssExploit = str(data[6])
        
        return data
         
def checkCVE(myCVE):
    '''
    Returning: CVE Published/Modified date and Description   
    '''    
    verifyCVE(myCVE)
    return (PublishedDate,ModifiedDate,vulnDescription)


def checkCVSS(myCVE):
    '''
    Returning:  CVSS v2 Base, Impact and  Exploit Scores    
    '''    
    
    verifyCVE(myCVE)
    return (cvssBase,cvssImpact,cvssExploit)

def checkReferences(myCVE):
    '''
    Returning:  CVE references and their IDs  
    '''   

    verifyCVE(myCVE)
    
    cveRef_id = []
    cveRef_Link = []
    cur = connDb()  
    cur.execute("select * from cve_reference where cveid='%s' " % myCVE)
    
    for RefData in cur.fetchall():
        
        cveRef_id.append(str(RefData[0]))
        cveRef_Link.append(str(RefData[1]))
        
    return (cveRef_id,cveRef_Link)

def checkCWE(myCVE):
    '''
    Returning:  CWE ids  
    '''
    verifyCVE(myCVE)
  
    cveCWE_id = []
    cur = connDb()
    cur.execute("select cweid from cve_cwe where cveid='%s' " % myCVE)
    
    for cweid in cur.fetchall():
        
        cveCWE_id.append(str(cweid[0]))
        
    return cveCWE_id

def checkCPE(myCVE):
    '''
    Returning:  CWE ids  
    '''
    verifyCVE(myCVE)
    
    cveCPE_id = []
    cur = connDb()
    cur.execute("select cpeid from cve_cpe where cveid='%s' " % myCVE)
    
    for cpeid in cur.fetchall():
        
        cveCPE_id.append(str(cpeid[0]))
        
    return cveCPE_id

def checkMS(myCVE):
    '''
    Returning:  Microsoft Patch Reference MS
    '''   

    verifyCVE(myCVE)
    
    cveMS_id = []
    cur = connDb()
    cur.execute("select * from map_cve_ms where cveid='%s' " % myCVE)
        
    for msid in cur.fetchall():
        
        cveMS_id.append(str(msid[0]))    
    
    return cveMS_id

def checkKB(myCVE):
    '''
    Returning:  Microsoft KB Reference 
    '''   

    verifyCVE(myCVE)
    
    cveKB_id = []
    cur = connDb()
    cur.execute("select * from map_cve_mskb where cveid='%s' " % myCVE)        
    

    for mskbid in cur.fetchall():
        
        cveKB_id.append(str(mskbid[0]))    
    
    return cveKB_id   


def checkAIXAPAR(myCVE):
    '''
    Returning:  IBM AIXAPAR
    '''   

    verifyCVE(myCVE)
    
    cveAIXAPAR_id = []
    cur = connDb()
    cur.execute("select * from map_cve_aixapar where cveid='%s' " % myCVE)        
    

    for aixaparid in cur.fetchall():
        
        cveAIXAPAR_id.append(str(aixaparid[0]))    
    
    return cveAIXAPAR_id   

def checkREDHAT(myCVE):
    '''
    Returning: REDHAT ids
    '''   

    verifyCVE(myCVE)
    
    cveREDHAT_id = []
    cur = connDb()
    cur.execute("select * from map_cve_redhat where cveid='%s' " % myCVE)        
    

    for redhatid in cur.fetchall():
        
        cveREDHAT_id.append(str(redhatid[0]))    
    
    return cveREDHAT_id 

def checkSUSE(myCVE):
    '''
    Returning: SUSE ids
    '''   

    verifyCVE(myCVE)
    
    cveSUSE_id = []
    cur = connDb()
    cur.execute("select * from map_cve_suse where cveid='%s' " % myCVE)        
    

    for suseid in cur.fetchall():
        
        cveSUSE_id.append(str(suseid[0]))    
    
    return cveSUSE_id 



def checkOVAL(myCVE):
    '''
    Returning:  OVAL ids and file link
    '''   

    verifyCVE(myCVE)
    
    cveOVAL_id = []
    cveOVAL_file = []
    cur = connDb()
    cur.execute("select ovalid from map_cve_oval where cveid='%s' " % myCVE)
    
    for ovalid in cur.fetchall():
        
        cveOVAL_id.append(str(ovalid[0]))
        cveOVAL_file.append(oval_url+str(ovalid[0]))
        
    return (cveOVAL_id,cveOVAL_file)   
   
def checkNESSUS(myCVE):
    '''
    Returning:  Nessus id, Script Name, Family Script, File Script
    '''   

    verifyCVE(myCVE)
    
    cveNESSUS_id = []
    cveNESSUS_file = []
    cveNESSUS_name = []
    cveNESSUS_family = []
    
    cur = connDb()
    cur.execute("select * from map_cve_nessus where cveid='%s' " % myCVE)
    
    for NessusData in cur.fetchall():
        cveNESSUS_id.append(str(NessusData[0]))
        cveNESSUS_file.append(str(NessusData[1]))
        cveNESSUS_name.append(str(NessusData[2]))
        cveNESSUS_family.append(str(NessusData[3]))
        
    return (cveNESSUS_id,cveNESSUS_file,cveNESSUS_name,cveNESSUS_family)      

def checkEDB(myCVE):
    '''
    Returning:  ExploitDB ids and exploit link
    '''   
    
    verifyCVE(myCVE)
    
    cveEDB_id = []
    cveEDB_file = []
    cur = connDb()
    cur.execute("select exploitdbid from map_cve_exploitdb where cveid='%s' " % myCVE)
    
    for exploitdbid in cur.fetchall():
        
        cveEDB_id.append(str(exploitdbid[0]))
        cveEDB_file.append(edb_url+str(exploitdbid[0]))
        
    return (cveEDB_id,cveEDB_file)

def checkRISK(myCVE):
    '''
    Returning:  Severity Level, Highest Severity Level and PCI Status
    topVulnerable means cvssBase=cvssImpact=cvssExploit =  10
    '''   

    cvssBase,cvssImpact,cvssExploit = checkCVSS(myCVE)    
    
    isTopVulnerable = False
    PCIstatus = "Passed"
       
    if cvssBase >= "7.0":
        levelSeverity = "High"
        PCIstatus = "Failed"

    if cvssBase >= "4.0" and cvssBase <= "6.9":
        levelSeverity = "Moderate"        

    if cvssBase >= "0.1" and cvssBase <= "3.9":
        levelSeverity = "Low"  
    
    if cvssBase == "10.0" and cvssImpact == "10.0" and cvssExploit == "10.0":
        levelSeverity = "High"
        isTopVulnerable = True
        PCIstatus = "Failed"

    return (levelSeverity,isTopVulnerable,PCIstatus)

def exportXML(myCVE):
    '''
    generate the vfeed xml format
    '''
    
    # define id
    vfeedid = myCVE.replace('CVE','vFeed')
    vfeedfile= myCVE.replace('-','_') +'.xml'

    # define generation time
    generated_on = strftime("%a, %d %b %Y %H:%M:%S", gmtime())

    # define the vFeed XML attributes
            
    root = Element('vFeed')
    root.set('xmlns:xsi', "http://www.w3.org/2001/XMLSchema-instance")
    root.set('xmlns:meta', "http://vfeed.toolswatch.org/0.1")
    root.set('xmlns', "http://vfeed.toolswatch.org/0.1")
    root.set('xsi:schemaLocation', "http://vfeed.toolswatch.org/0.1 http://vfeed.toolswatch.org/vfeed.xsd")
            
    root.append(Comment('#####################################'))
    root.append(Comment('Generated by vFeedApi.py'))
        
    head = SubElement(root, 'release')
    project_name = SubElement(head, 'name')
    project_name.text = 'vFeed XML for %s' %myCVE
    
    project_version = SubElement(head, 'version')
    project_version.text = __release__
    
    project_author = SubElement(head, 'author')
    project_author.text = '%s' %__author__
    
    project_url = SubElement(head, 'url')
    project_url.text = '%s' %__website__
    
    date_generated = SubElement(head, 'date_generated')
    date_generated.text = generated_on


    # Exporting  Vulnerability Summary
    
    PublishedDate,ModifiedDate,vulnDescription  = checkCVE(myCVE)
    
    root.append(Comment('#####################################'))
    root.append(Comment('Entry ID'))
    entry_head = SubElement(root, 'entry',
                    {'exported':str(vfeedfile),
                      'id':str(vfeedid),
                    })
            
    vul_summary_date  = SubElement(entry_head, 'date',
                            {'published':PublishedDate,
                             'modified':ModifiedDate,
                            })
            
    vul_summary = SubElement(entry_head, 'summary')
    vul_summary.text = vulnDescription
    vul_summary_ref = SubElement(entry_head, 'cve_ref')
    vul_summary_ref.text = "http://cve.mitre.org/cgi-bin/cvename.cgi?name="+ myCVE
    
     # Exporting references

    cveRef_id,cveRef_Link = checkReferences(myCVE)

    entry_head.append(Comment('#####################################'))
    entry_head.append(Comment('The Vulnerability References'))
    references_head = SubElement(entry_head, 'references')
    
    for i in range(0,len(cveRef_id)):
        source_head  = SubElement(references_head, 'source',
                        {'reference':str(cveRef_Link[i]),
                          'id':str(cveRef_id[i]),
                        })

    # Exporting Targets CPEs ids
    
    cveCPE_id = checkCPE(myCVE)
    
    if cveCPE_id:
        entry_head.append(Comment('#####################################'))
        entry_head.append(Comment('Vulnerable Targets according to CPE'))
        vulnerabletargets_head = SubElement(entry_head, 'vulnerableTargets')
                   
        for i in range(0,len(cveCPE_id)):
            cpe_head  = SubElement(vulnerabletargets_head, 'cpe',
                        {'id':str(cveCPE_id[i]),
                        })
                    

    # Exporting Risk Scoring

    levelSeverity,isTopVulnerable,PCIstatus = checkRISK(myCVE)
    cvssBase,cvssImpact,cvssExploit = checkCVSS(myCVE)

    entry_head.append(Comment('#####################################'))
    entry_head.append(Comment('Risk Scoring Evaluation'))
    riskscoring_head = SubElement(entry_head, 'riskScoring')
            
    risk_head  = SubElement(riskscoring_head, 'severityLevel',
                    {'status':levelSeverity,
                    })

    risk_head  = SubElement(riskscoring_head, 'cvss',
                    {'cvssvector':'not_defined_yet',
                      'base':cvssBase,
                      'impact':cvssImpact,
                       'exploit':cvssExploit,
                    })               
 
    risk_head  = SubElement(riskscoring_head, 'topVulnerable',
                    {'status':str(isTopVulnerable),
                    })

    risk_head  = SubElement(riskscoring_head, 'topAlert',
                    {'status':"not_defined_yet",
                     })
    
    risk_head  = SubElement(riskscoring_head, 'pciCompliance',
                    {'status':PCIstatus,
                    })

    # Exporting Patch Management
    
    entry_head.append(Comment('#####################################'))
    entry_head.append(Comment('Patch Management'))
    patchmanagement_head = SubElement(entry_head, 'patchManagement')
            
    ## Exporting Microsoft MS Patches
    
    cveMS_id = checkMS(myCVE)
    
    for i in range(0,len(cveMS_id)):        
        patch_head  = SubElement(patchmanagement_head, 'patch',
                        {'id':str(cveMS_id[i]),
                        'reference':'microsoft',
                        })
    
    ## Exporting Microsoft KB Patches    
    
    cveKB_id = checkKB(myCVE)
    
    for i in range(0,len(cveKB_id)):
        patch_head  = SubElement(patchmanagement_head, 'patch',
                        {'id':str(cveKB_id[i]),
                         'reference':'microsoft KB',
                        })  
            
  
    ## Exporting IBM AIXAPAR Patches
    
    cveAIXAPAR_id = checkAIXAPAR(myCVE)
    
    for i in range(0,len(cveAIXAPAR_id)):        
        patch_head  = SubElement(patchmanagement_head, 'patch',
                        {'id':str(cveAIXAPAR_id[i]),
                        'reference':'IBM',
                        })

    ## Exporting REDHAT Patches
    
    cveREDHAT_id = checkREDHAT(myCVE)
    
    for i in range(0,len(cveREDHAT_id)):        
        patch_head  = SubElement(patchmanagement_head, 'patch',
                        {'id':str(cveREDHAT_id[i]),
                        'reference':'REDHAT',
                        })

    ## Exporting SUSE Patches
    
    cveSUSE_id = checkSUSE(myCVE)
    
    for i in range(0,len(cveSUSE_id)):        
        patch_head  = SubElement(patchmanagement_head, 'patch',
                        {'id':str(cveSUSE_id[i]),
                        'reference':'SUSE',
                        })



    # Attack and Weaknesses Patterns
    
    cveCWE_id = checkCWE(myCVE)
    if cveCWE_id:
        
        entry_head.append(Comment('#####################################'))
        entry_head.append(Comment('Attack and Weaknesses Categories. Useful when performing classification of threats'))
        attackclassification_head = SubElement(entry_head, 'attackPattern')
        
        for i in range(0,len(cveCWE_id)):
            attackPattern_head  = SubElement(attackclassification_head, 'source',
                                    {'standard':'CWE - Common Weakness Enumeration',
                                     'id':str(cveCWE_id[i]),
                                     'title': "not_implemented_yet"
                                     })


    # Exporting Assessment, security tests and exploitation
    
    cveOVAL_id,cveOVAL_file = checkOVAL(myCVE)
    cveNESSUS_id,cveNESSUS_file,cveNESSUS_name,cveNESSUS_family = checkNESSUS(myCVE)
    cveEDB_id,cveEDB_file = checkEDB(myCVE)
    
    entry_head.append(Comment('#####################################'))
    entry_head.append(Comment('Assessment and security Tests. The IDs and source could be leveraged to test the vulnerability'))
    securitytest_head = SubElement(entry_head, 'assessment')

    ## Exporting OVAL ids    
    for i in range(0,len(cveOVAL_id)):
        ovalChecks_head  = SubElement(securitytest_head, 'check',
                                 {'type':'Local Security Testing',
                                  'id':str(cveOVAL_id[i]),
                                  'utility': "OVAL Interpreter",
                                  'file' :str(cveOVAL_file[i]),
                                  })
        
    ## Exporting Nessus attributes         
    for i in range(0,len(cveNESSUS_id)):
        nessusChecks_head  = SubElement(securitytest_head, 'check',
                                 {'type':'Remote Security Testing',
                                  'id':str(cveNESSUS_id[i]),
                                  'name':str(cveNESSUS_name[i]),
                                  'family':str(cveNESSUS_family[i]),
                                  'file' :str(cveNESSUS_file[i]),
                                  'utility': "Nessus Vulnerability Scanner",
                                  })     
    ## Exporting EDB ids 
    for i in range(0,len(cveEDB_id)):
        exploitChecks_head  = SubElement(securitytest_head, 'check',
                                 {'type':'Exploitation',
                                  'utility':"exploit-db",
                                  'id':str(cveEDB_id[i]),
                                  'file' : str(cveEDB_file[i]),
                                  })  

    ## Exporting xml vfeed file

    f1=open(vfeedfile, 'w+')
    #print prettify(root)
    print '[info] vFeed xml file %s exported for %s' %(vfeedfile,myCVE)
    print >> f1,prettify(root)


def prettify(elem):
    """Return a pretty-printed XML string for the Element.
    This function found on internet.
    """
    rough_string = ElementTree.tostring(elem, 'UTF-8')
    reparsed = minidom.parseString(rough_string)
    return reparsed.toprettyxml(indent="  ")