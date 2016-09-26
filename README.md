vFeed The Correlated Vulnerability and Threat Intelligence Database API
=======================================================================
![vFeed](http://www.vfeed.io/wp-content/uploads/2016/07/vfeed.png)

[![Build Status](https://travis-ci.org/toolswatch/vFeed.svg?branch=v0.6.5)](https://travis-ci.org/toolswatch/vFeed)
[![Code Health](https://landscape.io/github/toolswatch/vFeed/master/landscape.svg?style=flat)](https://landscape.io/github/toolswatch/vFeed/master)
[![Compatibility](https://img.shields.io/badge/CWE-Compatible-yellow.svg)](http://cwe.mitre.org/compatible/organizations.html#ToolsWatch)
[![Compatibility](https://img.shields.io/badge/CVE-Compatible-yellow.svg)](https://cve.mitre.org/compatible/compatible.html#ToolsWatch)
[![Compatibility](https://img.shields.io/badge/OVAL-Compatible-yellow.svg)](http://oval.mitre.org/adoption/participants.html#ToolsWatch)

**vFeed API / Database** is a CVE, CWE, and OVAL Compatible naming scheme concept that provides extra structured detailed third-party references and technical characteristics for a CVE entry through an extensible XML/JSON schema.
It also improves the reliability of CVEs by providing a flexible and comprehensive vocabulary for describing the relationship with other standards and security references.

vFeed API generates a JSON-based format outputs to describe in detail vulnerabilities. 
It can be leveraged as input by security researchers, practitioners, and tools as part of their vulnerability description. The standard syntax is easy to interpret by humans and systems.

The mandatory associated **vFeed DB (The Correlated Vulnerability and Threat Intelligence Database)** is a detective and preventive security information repository used for gathering vulnerability and mitigation data from scattered internet sources into an unified database. The vFeed DB must be obtained directly from [vFeed IO](http://www.vfeed.io).

* Open security standards:
    * [CVE](http://cve.mitre.org)
    * [CWE](http://cwe.mitre.org)
    * [CPE](http://cpe.mitre.org) 
    * [OVAL](http://oval.mitre.org) 
    * [CAPEC](http://capec.mitre.org) 
    * [CVSS](http://www.first.org/cvss)
    * [WASC](http://projects.webappsec.org/w/page/13246978/Threat%20Classification)

* Vulnerability Assessment & Exploitation IDs (Metasploit, SAINT Corporation, Tenable's Nessus Plugin IDs, Nmap, Exploit-DB)
* Vendors Security Alerts:
    * Microsoft MS
    * Mandriva
    * Redhat
    * Cisco
    * Sun
    * Gentoo
    * Ubuntu
    * And more ...


Key features
=================

* Registered as CVE, CWE, and OVAL Compatible by the Mitre Corporation
* Support Open Standards such as CVE, CPE, CWE, CAPEC, CVSS and more
* Downloadable Correlated Vulnerability and Threat Intelligence Database 
* Support correlation with 3rd-party security references IAVA, OVAL etc
* Support correlation with security assessment and patch vendors (Nessus, Exploit-DB, Redhat, Microsoft..)
* Simple and ready-to-use API Python 

More features at [vFeed IO](http://www.vfeed.io/features/).

Target Audience
=================

* Penetration testers who want to analyze CVEs and gather extra information to help shape avenues to exploit vulnerabilities.
* Security auditors who want to report accurate information about findings. vFeed could be the best way to describe a CVE with attributes based on standards and 3rd party references as vendors or companies involved into standarization efforts.
* Security tools vendors / security open source developers who need to implement libraries to enumerate useful information about CVEs without wasting time to correlate and to create a proprietary database. vFeed is by far the best solution. Methods can be invoked from programs or scripts with a simple call.
* Any security hacker who is conducting research and needs a very fast and accurate way to enumerate available exploits or techniques to check a vulnerability.


How to ?
==============

Run `vfeedcli.py -h` for help.
Refer to the [wiki](https://github.com/toolswatch/vFeed/wiki/) page for detailed documentation.
 

Latest release
==============

0.6.9
-----
* The vFeed DB is no more available through `update` command. The command is deprecated. 
* The delivery of the vFeed DB was handed over to a new established entity [vFeed IO](http://www.vfeed.io). This entity sets the goal to become the Leading Provider of Vulnerability and Threat Intelligence Database.
* The API has been modified to reflect the new changes. 


0.6.8
-----
* Added support to CAPEC version 2.8. Check [about CAPEC v2.8](http://capec.mitre.org/news/index.html#december72015_CAPEC_List_Version_2.8_Now_Available).
* Added support to CWE v2.9. Check [the full changelog](http://cwe.mitre.org/data/reports/diff_reports/v2.8_v2.9.html).
* Added mapping to [WASC v2.0 Threat Classification](http://projects.webappsec.org/w/page/13246978/Threat%20Classification).
* Added CVSS v2.0 vectors to `risk.py` class. Now, the methods `get_cvss` and `get_severity` display the vector when available.
* Added new method `get_wasc` to reflect the new mapping with WASC v2.0. The method returns ID, Title and URL when available.
* Modified the method `get_capec` to return the following:
    * The title
    * [Method of Attacks](http://capec.mitre.org/documents/schema/schema_v2.7.1.html#Method_of_Attack%20%28Methods_of_Attack%29)
    * [Mitigations](http://capec.mitre.org/documents/schema/schema_v2.7.1.html#Solution_or_Mitigation)
* Reflected the changes in `cvsexports.sql` MongoDB script to generate the new added tables.
* vFeed.db the correlated vulnerability & threat database fully regenerated to support the new changes.
* Documentation updated accordingly.

**NOTE**: Some code was cleaned. Nevertheless, the issues reported [here](https://github.com/toolswatch/vFeed/issues) will be fixed in next minor version.


0.6.7
---------
* Added support to [Landscape](https://landscape.io) with some code cleaning.

0.6.6
---------
* Modified the `update.py` class to display the vFeed License before downloading the database.
