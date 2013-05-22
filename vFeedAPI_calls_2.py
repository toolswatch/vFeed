#!/usr/bin/env python

__author__ = 'NJ OUCHN'
__email__ = 'hacker@toolswatch.org'
__website__= 'http://www.toolswatch.org'
__release__ = 'vFeed b0.2'


import sys
import os
from lib import vFeedApi
'''
vFeedAPI_calls_2.py -  Sample script to test available methods.

methods :

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
- checkRISK
- exportXML

'''

def call_checkCVE(myCVE):
    PublishedDate,ModifiedDate,vulnDescription  = vFeedApi.checkCVE(myCVE)
    print '[cve_description]:',vulnDescription
    print '[cve_published]:',PublishedDate
    print '[cve_modified]:',ModifiedDate
    

def call_checkCVSS(myCVE):
    cvssBase,cvssImpact,cvssExploit = vFeedApi.checkCVSS(myCVE)
    print '[cvss_base]:', cvssBase
    print '[cvss_impact]:',cvssImpact
    print '[cvss_exploit]:',cvssExploit 


def call_checkReferences(myCVE):
    # as you notice, this method returns a list.
    
    cveRef_id,cveRef_Link = vFeedApi.checkReferences(myCVE)
   
    for i in range(0,len(cveRef_id)):
        print '[reference_id]:', cveRef_id[i]
        print '[reference_link]', cveRef_Link[i]

    print ''
    print '[stats] %s has %d references' %(myCVE,len(cveRef_id))

def call_checkCWE(myCVE):
    # as you notice, this method returns a list.
    
    cveCWE_id = vFeedApi.checkCWE(myCVE)
    
    for i in range(0,len(cveCWE_id)):
        print '[cwe_id]:', cveCWE_id[i]

    print ''
    print '[stats] %s has %d CWE' %(myCVE,len(cveCWE_id))

def  call_checkCPE(myCVE):
    # as you notice, this method returns a list.
    
    cveCPE_id = vFeedApi.checkCPE(myCVE)

    for i in range(0,len(cveCPE_id)):
        print '[cpe_id]:', cveCPE_id[i]

    print ''
    print '[stats] %s has %d CPE' %(myCVE,len(cveCPE_id))

def  call_checkOVAL(myCVE):
    # as you notice, this method returns a list.
    
    cveOVAL_id,cveOVAL_file = vFeedApi.checkOVAL(myCVE)
    
    for i in range(0,len(cveOVAL_id)):
        print '[oval_id]:', cveOVAL_id[i]
        print '[oval_file]:', cveOVAL_file[i]
    
    print ''
    print '[stats] %s has %d OVAL definition(s)' %(myCVE,len(cveOVAL_id))

def  call_checkNESSUS(myCVE):
    # as you notice, this method returns a list.

    cveNESSUS_id,cveNESSUS_file,cveNESSUS_name,cveNESSUS_family = vFeedApi.checkNESSUS(myCVE)
    
    for i in range(0,len(cveNESSUS_id)):
        print '[nessus_id]:', cveNESSUS_id[i]
        print '[nessus_file]:', cveNESSUS_file[i]
        print '[nessus_name]:', cveNESSUS_name[i]
        print '[nessus_family]:', cveNESSUS_family[i]
    
    print ''
    print '[stats] %s has %d Nessus testing script(s)' %(myCVE,len(cveNESSUS_id))


def  call_checkEDB(myCVE):
    # as you notice, this method returns a list.

    cveEDB_id,cveEDB_file = vFeedApi.checkEDB(myCVE)
  
    for i in range(0,len(cveEDB_id)):
        print '[edb_id]:', cveEDB_id[i]
        print '[edb_exploit]:', cveEDB_file[i]
    
    print ''
    print '[stats] %s has %d Exploit-DB exploit(s)' %(myCVE,len(cveEDB_id))


def  call_checkMS(myCVE):
    # as you notice, this method returns a list.
    
    cveMS_id = vFeedApi.checkMS(myCVE)
    
    for i in range(0,len(cveMS_id)):
        print '[Microsoft_MS_id]:', cveMS_id[i]
        
    print ''
    print '[stats] %s has %d Microsoft MS Patch(s)' %(myCVE,len(cveMS_id))

def  call_checkKB(myCVE):
    # as you notice, this method returns a list.
    
    cveKB_id = vFeedApi.checkKB(myCVE)
    
    for i in range(0,len(cveKB_id)):
        print '[Microsoft_KB_id]:', cveKB_id[i]
        
    print ''
    print '[stats] %s has %d Microsoft KB bulletin(s)' %(myCVE,len(cveKB_id))

def  call_checkAIXAPAR(myCVE):
    # as you notice, this method returns a list.
    
    cveAIXAPAR_id = vFeedApi.checkAIXAPAR(myCVE)
    
    for i in range(0,len(cveAIXAPAR_id)):
        print '[IBM_AIXAPAR_id]:', cveAIXAPAR_id[i]
        
    print ''
    print '[stats] %s has %d IBM AIX APAR(s)' %(myCVE,len(cveAIXAPAR_id))

def  call_checkREDHAT(myCVE):
    # as you notice, this method returns a list.
    
    cveREDHAT_id = vFeedApi.checkREDHAT(myCVE)
    
    for i in range(0,len(cveREDHAT_id)):
        print '[REDHAT_id]:', cveREDHAT_id[i]
        
    print ''
    print '[stats] %s has %d REDHAT id(s)' %(myCVE,len(cveREDHAT_id))

def  call_checkSUSE(myCVE):
    # as you notice, this method returns a list.
    
    cveSUSE_id = vFeedApi.checkSUSE(myCVE)
    
    for i in range(0,len(cveSUSE_id)):
        print '[SUSE_id]:', cveSUSE_id[i]
        
    print ''
    print '[stats] %s has %d SUSE id(s)' %(myCVE,len(cveSUSE_id))

def  call_checkRISK(myCVE):
    
    levelSeverity,isTopVulnerable,PCIstatus = vFeedApi.checkRISK(myCVE)
    print '[cve_severity]:',levelSeverity
    print '[cve_isTopVulnerable]:',isTopVulnerable
    print '[cve_pcistatus]:',PCIstatus


def main():
    
    if len(sys.argv) == 3:
        myCVE = sys.argv[2]
        apiMethod = sys.argv[1]
        
    else:
        print ''        
        print '[ver] %s' %__release__
        print '[info] usage: ' + str(sys.argv[0]) + ' <API Method> <CVE id>'
        print ''
        print '[info] available API methods:'
        print 'checkCVE | checkCPE | checkCVSS | checkCWE | checkReferences | checkRISK'
        print 'checkOVAL | checkNESSUS | checkEDB'
        print 'checkMS | checkKB | checkAIXAPAR | checkREDHAT | checkSUSE'
        print 'exportXML (for exporting the vFeed XML file)'
        exit(0)
    
    if apiMethod == "checkCVE":
        call_checkCVE(myCVE)
        exit(0)

    if apiMethod == "checkCVSS":
        call_checkCVSS(myCVE)
        exit(0)

    if apiMethod == "checkReferences":
        call_checkReferences(myCVE)
        exit(0)

    if apiMethod == "checkCWE":
        call_checkCWE(myCVE)        
        exit(0)

    if apiMethod == "checkCPE":
        call_checkCPE(myCVE)           
        exit(0)

    if apiMethod == "checkOVAL":
        call_checkOVAL(myCVE)   
        exit(0)

    if apiMethod == "checkNESSUS":
        call_checkNESSUS(myCVE)   
        exit(0)

    if apiMethod == "checkEDB":
        call_checkEDB(myCVE)   
        exit(0)

    if apiMethod == "checkMS":
        call_checkMS(myCVE)   
        exit(0)

    if apiMethod == "checkKB":
        call_checkKB(myCVE)   
        exit(0)

    if apiMethod == "checkAIXAPAR":
        call_checkAIXAPAR(myCVE) 
        exit(0)

    if apiMethod == "checkREDHAT":
        call_checkREDHAT(myCVE) 
        exit(0)

    if apiMethod == "checkSUSE":
        call_checkSUSE(myCVE) 
        exit(0)

    if apiMethod == "checkRISK":
        call_checkRISK(myCVE)  
        exit(0)

    if apiMethod == "exportXML":
        vFeedApi.exportXML(myCVE)
        exit(0)
    
    else:
        print'[error] the method %s is not implemented yet' % apiMethod
    
           
if __name__ == '__main__':
    main()   