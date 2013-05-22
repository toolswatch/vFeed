#!/usr/bin/env python

__author__ = 'NJ OUCHN'
__email__ = 'hacker@toolswatch.org'
__website__= 'http://www.toolswatch.org'
__release__ = 'vFeed b0.2'

from lib import vFeedApi

'''
vFeedAPI_calls_1.py -  Sample script to call methods from your programs

'''

# Method 1 : Exporting of the XML vFeed
# the exportXML methods generates an xml file related to the CVE id.

foundCVE = "CVE-2007-3091"
print '[info] exporting %s to vFeed format' %foundCVE
vFeedApi.exportXML(foundCVE)

# Method 2 : checking for the CVSS scores. W
# we call the appropriate method checkCVSS.
# checkCVSS returns 3 values.
# for more information see vFeedAPI_calls_2.py or read the documentation.


foundCVE2= "CVE-2007-6439"
print '[info] CVSS v2 scores for %s' %foundCVE2

cvssBase,cvssImpact,cvssExploit = vFeedApi.checkCVSS(foundCVE2)
print '\t [cvss_base]:', cvssBase
print '\t [cvss_impact]:',cvssImpact
print '\t [cvss_exploit]:',cvssExploit

# Method 3 : checking for the Nessus attribues. 
# we call the appropriate method checkCVSS.
# checkNESSUS returns 4 values.
# note that this method returns a list.
# for more information see vFeedAPI_calls_2.py or read the documentation

foundCVE3= "CVE-2007-5200"
print '[info] Nessus Information for %s' %foundCVE3

cveNESSUS_id,cveNESSUS_file,cveNESSUS_name,cveNESSUS_family = vFeedApi.checkNESSUS(foundCVE3)    
for i in range(0,len(cveNESSUS_id)):
    print '\t [nessus_id]:', cveNESSUS_id[i]
    print '\t [nessus_file]:', cveNESSUS_file[i]
    print '\t [nessus_name]:', cveNESSUS_name[i]
    print '\t [nessus_family]:', cveNESSUS_family[i]
    
    

