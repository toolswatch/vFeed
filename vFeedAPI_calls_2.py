#!/usr/bin/env python


import sys
from lib import vFeedApi
'''
vFeedAPI_calls_2.py -  Sample script to test available methods.

methods :

- checkCVE
- checkCVSS
- checkREF (changed from checkReferences)
- checkCWE
- checkCPE
- checkOVAL
- checkNESSUS
- checkEDB
- checkSAINT
- checkMS
- checkKB
- checkAIXAPAR
- checkREDHAT
- checkDEBIAN
- checkMANDRIVA
- checkRISK
- exportXML

'''


def call_checkCVE():
    cveInfo = vfeed.checkCVE()
    if cveInfo:
        print '[cve_description]:', cveInfo['cveDescription']
        print '[cve_published]:', cveInfo['publishedDate']
        print '[cve_modified]:', cveInfo['modifiedDate']


def call_checkCVSS():
    cvssScore = vfeed.checkCVSS()
    if cvssScore:
        print '[cvss_base]:', cvssScore['base']
        print '[cvss_impact]:', cvssScore['impact']
        print '[cvss_exploit]:', cvssScore['exploit']


def call_checkREF():

    cveRef = vfeed.checkREF()
    for i in range(0, len(cveRef)):
        print '[reference_id]:', cveRef[i]['id']
        print '[reference_link]', cveRef[i]['link']
    print ''
    print '[stats] %d Reference(s)' % len(cveRef)


def call_checkCWE():

    cveCWE = vfeed.checkCWE()
    for i in range(0, len(cveCWE)):
        print '[cwe_id]:', cveCWE[i]['id']
    print ''
    print '[stats] %d CWE(s) ' % len(cveCWE)


def  call_checkCPE():

    cveCPE = vfeed.checkCPE()
    for i in range(0, len(cveCPE)):
        print '[cpe_id]:', cveCPE[i]['id']

    print ''
    print '[stats] %d CPE(s)' % len(cveCPE)


def  call_checkOVAL():

    cveOVAL = vfeed.checkOVAL()
    for i in range(0, len(cveOVAL)):
        print '[oval_id]:', cveOVAL[i]['id']
        print '[oval_file]:', cveOVAL[i]['file']

    print ''
    print '[stats] %d OVAL definition(s)' % len(cveOVAL)


def  call_checkNESSUS():

    cveNessus = vfeed.checkNESSUS()
    for i in range(0, len(cveNessus)):
        print '[nessus_id]:', cveNessus[i]['id']
        print '[nessus_name]:', cveNessus[i]['name']
        print '[nessus_file]:', cveNessus[i]['file']
        print '[nessus_family]:', cveNessus[i]['family']

    print ''
    print '[stats] %d Nessus testing script(s)' % len(cveNessus)


def  call_checkEDB():

    cveEDB = vfeed.checkEDB()
    for i in range(0, len(cveEDB)):
        print '[edb_id]:', cveEDB[i]['id']
        print '[edb_exploit]:', cveEDB[i]['file']

    print ''
    print '[stats] %d Exploit-DB exploit(s)' % len(cveEDB)


def  call_checkSAINT():

    cveSAINT = vfeed.checkSAINT()
    for i in range(0, len(cveSAINT)):
        print '[SAINTEXPLOIT_id]:', cveSAINT[i]['id']
        print '[SAINTEXPLOIT_TITLE]:', cveSAINT[i]['title']
        print '[SAINTEXPLOIT_FILE]:', cveSAINT[i]['file']

    print ''
    print '[stats] %d SAINT EXPLOIT id(s)' % len(cveSAINT)


def  call_checkMS():

    cveMS = vfeed.checkMS()
    for i in range(0, len(cveMS)):
        print '[Microsoft_MS_id]:', cveMS[i]['id']

    print ''
    print '[stats] %d Microsoft MS Patch(s)' % len(cveMS)


def  call_checkKB():

    cveKB = vfeed.checkKB()
    for i in range(0, len(cveKB)):
        print '[Microsoft_KB_id]:', cveKB[i]['id']

    print ''
    print '[stats] %d Microsoft KB bulletin(s)' % len(cveKB)


def  call_checkAIXAPAR():

    cveAIX = vfeed.checkAIXAPAR()
    for i in range(0, len(cveAIX)):
        print '[IBM_AIXAPAR_id]:', cveAIX[i]['id']

    print ''
    print '[stats] %d IBM AIX APAR(s)' % len(cveAIX)


def  call_checkREDHAT():

    cveRHEL, cveBUGZILLA = vfeed.checkREDHAT()
    for i in range(0, len(cveRHEL)):
        print '[REDHAT_id]:', cveRHEL[i]['id']
        print '[REDHAT_PATCH_TITLE]:', cveRHEL[i]['title']
        print '[REDHAT_OVAL_ID]:', cveRHEL[i]['oval']

    print ''
    print '[stats] %d REDHAT id(s)' % len(cveRHEL)

    for i in range(0, len(cveBUGZILLA)):
        print '[REDHAT_BUGZILLA_ISSUED]:', cveBUGZILLA[i]['date_issue']
        print '[REDHAT_BUGZILLA_id]:', cveBUGZILLA[i]['id']
        print '[REDHAT_BUGZILLA_title]:', cveBUGZILLA[i]['title']
    print 'total found Bugzilla', len(cveBUGZILLA)


def  call_checkSUSE():

    cveSUSE = vfeed.checkSUSE()
    for i in range(0, len(cveSUSE)):
        print '[SUSE_id]:', cveSUSE[i]['id']

    print ''
    print '[stats] %d SUSE id(s)' % len(cveSUSE)


def  call_checkDEBIAN():

    cveDEBIAN = vfeed.checkDEBIAN()
    for i in range(0, len(cveDEBIAN)):
        print '[DEBIAN_id]:', cveDEBIAN[i]['id']

    print ''
    print '[stats] %d DEBIAN id(s)' % len(cveDEBIAN)


def  call_checkMANDRIVA():

    cveMANDRIVA = vfeed.checkMANDRIVA()
    for i in range(0, len(cveMANDRIVA)):
        print '[MANDRIVA_id]:', cveMANDRIVA[i]['id']

    print ''
    print '[stats] %d MANDRIVA id(s)' % len(cveMANDRIVA)


def  call_checkRISK():

    cveRISK = vfeed.checkRISK()
    print 'Severity:', cveRISK['severitylevel']
    print 'top vulnerablity:', cveRISK['topvulnerable']
    print 'pci compliance:', cveRISK['pciCompliance']


def main():

    global vfeed

    info = vFeedApi.vFeedInfo()

    if len(sys.argv) == 3:
        myCVE = sys.argv[2]
        apiMethod = sys.argv[1]

    else:
        print ''
        print '-----------------------------------------------------------'
        print info.get_version()['title']
        print '                                         version ' + info.get_version()['build']
        print '-----------------------------------------------------------'
        print ''
        print '[usage]: ' + str(sys.argv[0]) + ' <API Method> <CVE id>'
        print ''
        print '[info] available API methods:'
        print 'checkCVE | checkCPE | checkCVSS | checkCWE | checkREF | checkRISK'
        print 'checkOVAL | checkNESSUS | checkEDB | checkSAINT'
        print 'checkMS | checkKB | checkAIXAPAR | checkREDHAT | checkSUSE | checkDEBIAN | checkMANDRIVA'
        print 'exportXML (for exporting the vFeed XML file)'
        exit(0)

    vfeed = vFeedApi.vFeed(myCVE)

    if apiMethod == "checkCVE":
        call_checkCVE()
        exit(0)

    if apiMethod == "checkCVSS":
        call_checkCVSS()
        exit(0)

    if apiMethod == "checkREF":
        call_checkREF()
        exit(0)

    if apiMethod == "checkCWE":
        call_checkCWE()
        exit(0)

    if apiMethod == "checkCPE":
        call_checkCPE()
        exit(0)

    if apiMethod == "checkOVAL":
        call_checkOVAL()
        exit(0)

    if apiMethod == "checkNESSUS":
        call_checkNESSUS()
        exit(0)

    if apiMethod == "checkEDB":
        call_checkEDB()
        exit(0)

    if apiMethod == "checkSAINT":
        call_checkSAINT()
        exit(0)

    if apiMethod == "checkMS":
        call_checkMS()
        exit(0)

    if apiMethod == "checkKB":
        call_checkKB()
        exit(0)

    if apiMethod == "checkAIXAPAR":
        call_checkAIXAPAR()
        exit(0)

    if apiMethod == "checkREDHAT":
        call_checkREDHAT()
        exit(0)

    if apiMethod == "checkDEBIAN":
        call_checkDEBIAN()
        exit(0)

    if apiMethod == "checkMANDRIVA":
        call_checkMANDRIVA()
        exit(0)

    if apiMethod == "checkSUSE":
        call_checkSUSE()
        exit(0)

    if apiMethod == "checkRISK":
        call_checkRISK()
        exit(0)

    if apiMethod == "exportXML":
        vfeed.exportXML()
        exit(0)

    else:
        print'[error] the method %s is not implemented' % apiMethod


if __name__ == '__main__':
    main()
