#!/usr/bin/env python


from vfeed import vFeed, vFeedInfo

'''
vFeedAPI_calls_1.py -  Sample script to call methods from your programs

'''

# create an instance of the class vFeedInfo
print '[instance] creating an instance with vFeedApi.vFeedInfo() '
info = vFeedInfo()

print '[invoking] the get_version() method '
print 'version: ', info.get_version()['build']

print '[invoking] the get_owner() method '
print 'author (if you want to get in touch and say hello):', info.get_owner()['author']

print '[invoking] the get_config() method (note that the values are returned in dict. You can then read any key value you need ..'
print 'vFeed global config returned as dict:', info.get_config()['primary']


# Invoking the vFeed class

#cve = "CVE-2008-1447"
cve = "CVE-2013-3238"
print '[setting] using cve ', cve

# create an instance of the class vFeed and pass the CVE
print '[instance] creating an instance with vFeedApi.vFeed(cve) '
vfeed = vFeed(cve)


print '[invoking] the checkCVE() method '
# invoking the checkCVE method
cveInfo = vfeed.checkCVE()

if cveInfo:

# returned data is a dictionary with 3 keys.
    print 'description: ', cveInfo['cveDescription']
    print 'published date: ', cveInfo['publishedDate']
    print 'modified date: ', cveInfo['modifiedDate']


# invoking the checkCVSS method

print '[invoking] the checkCVSS() method '
cvssScore = vfeed.checkCVSS()

if cvssScore:
    print 'base score:', cvssScore['base']
    print 'impact score:', cvssScore['impact']
    print 'exploit score:', cvssScore['exploit']


# invoking the checkREF method (it's not longer checkReferences)
print '[invoking] the checkREF() method '
cveRef = vfeed.checkREF()
for i in range(0, len(cveRef)):
    print 'ref id:', cveRef[i]['id']
    print 'ref link', cveRef[i]['link']
print 'total found REF', len(cveRef)

# invoking the checkCWE method
print '[invoking] the checkCWE() method '
cveCWE = vfeed.checkCWE()
for i in range(0, len(cveCWE)):
    print 'CWE id:', cveCWE[i]['id']
print 'total found CWE', len(cveCWE)

# invoking the checkCPE method
print '[invoking] the checkCPE() method '
cveCPE = vfeed.checkCPE()
for i in range(0, len(cveCPE)):
    print 'CPE id:', cveCPE[i]['id']
print 'total found CPE', len(cveCPE)

print '[invoking] the checkMS() method '
cveMS = vfeed.checkMS()
for i in range(0, len(cveMS)):
    print 'Microsoft MS id:', cveMS[i]['id']
print 'total found MS', len(cveMS)

print '[invoking] the checkKB() method '
cveKB = vfeed.checkKB()
for i in range(0, len(cveKB)):
    print 'Microsoft KB id:', cveKB[i]['id']
print 'total found KB', len(cveKB)

print '[invoking] the checkAIXAPAR() method '
cveAIX = vfeed.checkAIXAPAR()
for i in range(0, len(cveAIX)):
    print 'AIX APAR id:', cveAIX[i]['id']
print 'total found AIXAPAR', len(cveAIX)

print '[invoking] the checkREDHAT() method '
cveRHEL, cveBUGZ = vfeed.checkREDHAT()
for i in range(0, len(cveRHEL)):
    print 'REDHAT id:', cveRHEL[i]['id']
    print 'REDHAT Patch Title:', cveRHEL[i]['title']
    print 'REDHAT OVAL ID:', cveRHEL[i]['oval']
print 'total found REDHAT', len(cveRHEL)

for i in range(0, len(cveBUGZ)):
    print 'Bugzilla date:', cveBUGZ[i]['date_issue']
    print 'Bugzilla id :', cveBUGZ[i]['id']
    print 'Bugzilla title :', cveBUGZ[i]['title']
print 'total found Bugzilla', len(cveBUGZ)


print '[invoking] the checkDEBIAN() method '
cveDEB = vfeed.checkDEBIAN()

for i in range(0, len(cveDEB)):
    print 'DEBIAN id:', cveDEB[i]['id']
print 'total found DEBIAN', len(cveDEB)

print '[invoking] the checkSUSE() method '
cveSUSE = vfeed.checkSUSE()
for i in range(0, len(cveSUSE)):
    print 'SUSE id:', cveSUSE[i]['id']
print 'total found SUSE', len(cveSUSE)

print '[invoking] the checkMANDRIVA() method '
cveMANDRIVA = vfeed.checkMANDRIVA()
for i in range(0, len(cveMANDRIVA)):
    print 'MANDRIVA id:', cveMANDRIVA[i]['id']
print 'total found MANDRIVA', len(cveMANDRIVA)


print '[invoking] the checkOVAL() method '
cveOVAL = vfeed.checkOVAL()
for i in range(0, len(cveOVAL)):
    print 'OVAL id:', cveOVAL[i]['id']
    print 'OVAL file', cveOVAL[i]['file']
print 'total found OVAL', len(cveOVAL)

print '[invoking] the checkNESSUS() method '
cveNessus = vfeed.checkNESSUS()

for i in range(0, len(cveNessus)):
    print 'Nessus id:', cveNessus[i]['id']
    print 'Nessus name', cveNessus[i]['name']
    print 'Nessus file', cveNessus[i]['file']
    print 'Nessus family', cveNessus[i]['family']
print 'total found NESSUS', len(cveNessus)

print '[invoking] the checkEDB() method '
cveEDB = vfeed.checkEDB()

for i in range(0, len(cveEDB)):
    print 'EDB id:', cveEDB[i]['id']
    print 'EDB file', cveEDB[i]['file']
print 'total found EDB', len(cveEDB)

print '[invoking] the checkSAINT() method '
cveSAINTexp = vfeed.checkSAINT()
for i in range(0, len(cveSAINTexp)):
    print 'Saint Exploit id:', cveSAINTexp[i]['id']
    print 'Saint Exploit Title:', cveSAINTexp[i]['title']
    print 'Saint Exploit File:', cveSAINTexp[i]['file']
print 'total found Saint Exploit', len(cveSAINTexp)


print '[invoking] the checkRISK() method '
cveRISK = vfeed.checkRISK()
print 'Severity:', cveRISK['severitylevel']
print 'top vulnerability:', cveRISK['topvulnerable']
print 'pci compliance:', cveRISK['pciCompliance']


print '[Generating XML] Invoking the exportXML() method '
cve = "CVE-2008-1447"
#cve = "CVE-2013-3238"
print '[New Instance] Creating new instance with cve ', cve
vfeed = vFeed(cve)
vfeed.exportXML()
