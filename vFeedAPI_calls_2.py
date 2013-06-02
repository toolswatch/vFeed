#!/usr/bin/env python
import sys

from vfeed import vFeed, vFeedInfo

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


def call_checkCVE(vfeed):
    cveInfo = vfeed.checkCVE()
    if cveInfo:
        print '[cve_description]:', cveInfo['cveDescription']
        print '[cve_published]:', cveInfo['publishedDate']
        print '[cve_modified]:', cveInfo['modifiedDate']


def call_checkCVSS(vfeed):
    cvssScore = vfeed.checkCVSS()
    if cvssScore:
        print '[cvss_base]:', cvssScore['base']
        print '[cvss_impact]:', cvssScore['impact']
        print '[cvss_exploit]:', cvssScore['exploit']


def call_checkREF(vfeed):

    cveRef = vfeed.checkREF()
    for i in range(0, len(cveRef)):
        print '[reference_id]:', cveRef[i]['id']
        print '[reference_link]', cveRef[i]['link']
    print ''
    print '[stats] %d Reference(s)' % len(cveRef)


def call_checkCWE(vfeed):

    cveCWE = vfeed.checkCWE()
    for i in range(0, len(cveCWE)):
        print '[cwe_id]:', cveCWE[i]['id']
    print ''
    print '[stats] %d CWE(s) ' % len(cveCWE)


def call_checkCPE(vfeed):

    cveCPE = vfeed.checkCPE()
    for i in range(0, len(cveCPE)):
        print '[cpe_id]:', cveCPE[i]['id']

    print ''
    print '[stats] %d CPE(s)' % len(cveCPE)


def call_checkOVAL(vfeed):

    cveOVAL = vfeed.checkOVAL()
    for i in range(0, len(cveOVAL)):
        print '[oval_id]:', cveOVAL[i]['id']
        print '[oval_file]:', cveOVAL[i]['file']

    print ''
    print '[stats] %d OVAL definition(s)' % len(cveOVAL)


def call_checkNESSUS(vfeed):

    cveNessus = vfeed.checkNESSUS()
    for i in range(0, len(cveNessus)):
        print '[nessus_id]:', cveNessus[i]['id']
        print '[nessus_name]:', cveNessus[i]['name']
        print '[nessus_file]:', cveNessus[i]['file']
        print '[nessus_family]:', cveNessus[i]['family']

    print ''
    print '[stats] %d Nessus testing script(s)' % len(cveNessus)


def call_checkEDB(vfeed):

    cveEDB = vfeed.checkEDB()
    for i in range(0, len(cveEDB)):
        print '[edb_id]:', cveEDB[i]['id']
        print '[edb_exploit]:', cveEDB[i]['file']

    print ''
    print '[stats] %d Exploit-DB exploit(s)' % len(cveEDB)


def call_checkSAINT(vfeed):

    cveSAINT = vfeed.checkSAINT()
    for i in range(0, len(cveSAINT)):
        print '[SAINTEXPLOIT_id]:', cveSAINT[i]['id']
        print '[SAINTEXPLOIT_TITLE]:', cveSAINT[i]['title']
        print '[SAINTEXPLOIT_FILE]:', cveSAINT[i]['file']

    print ''
    print '[stats] %d SAINT EXPLOIT id(s)' % len(cveSAINT)


def call_checkMS(vfeed):

    cveMS = vfeed.checkMS()
    for i in range(0, len(cveMS)):
        print '[Microsoft_MS_id]:', cveMS[i]['id']

    print ''
    print '[stats] %d Microsoft MS Patch(s)' % len(cveMS)


def call_checkKB(vfeed):

    cveKB = vfeed.checkKB()
    for i in range(0, len(cveKB)):
        print '[Microsoft_KB_id]:', cveKB[i]['id']

    print ''
    print '[stats] %d Microsoft KB bulletin(s)' % len(cveKB)


def call_checkAIXAPAR(vfeed):

    cveAIX = vfeed.checkAIXAPAR()
    for i in range(0, len(cveAIX)):
        print '[IBM_AIXAPAR_id]:', cveAIX[i]['id']

    print ''
    print '[stats] %d IBM AIX APAR(s)' % len(cveAIX)


def call_checkREDHAT(vfeed):

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


def call_checkSUSE(vfeed):

    cveSUSE = vfeed.checkSUSE()
    for i in range(0, len(cveSUSE)):
        print '[SUSE_id]:', cveSUSE[i]['id']

    print ''
    print '[stats] %d SUSE id(s)' % len(cveSUSE)


def call_checkDEBIAN(vfeed):

    cveDEBIAN = vfeed.checkDEBIAN()
    for i in range(0, len(cveDEBIAN)):
        print '[DEBIAN_id]:', cveDEBIAN[i]['id']

    print ''
    print '[stats] %d DEBIAN id(s)' % len(cveDEBIAN)


def call_checkMANDRIVA(vfeed):

    cveMANDRIVA = vfeed.checkMANDRIVA()
    for i in range(0, len(cveMANDRIVA)):
        print '[MANDRIVA_id]:', cveMANDRIVA[i]['id']

    print ''
    print '[stats] %d MANDRIVA id(s)' % len(cveMANDRIVA)


def call_checkRISK(vfeed):

    cveRISK = vfeed.checkRISK()
    print 'Severity:', cveRISK['severitylevel']
    print 'Top vulnerablity:', cveRISK['topvulnerable']
    print 'PCI compliance:', cveRISK['pciCompliance']


def main():

    info = vFeedInfo()

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

    vfeed = vFeed(myCVE)

    if apiMethod == "exportXML":
        vfeed.exportXML()
        exit(0)

    try:
        globals()['call_%s' % apiMethod](vfeed)
    except:
        print'[error] the method %s is not implemented' % apiMethod
    else:
        exit(0)


if __name__ == '__main__':
    main()
