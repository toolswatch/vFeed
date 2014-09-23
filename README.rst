vFeed.db SQLite Vulnerability Database & vFeed python API
=========================================================

vFeed framework is an open source naming scheme concept that provides extra structured detailed third-party references and technical characteristics for a CVE entry through an extensible XML schema.
It also improves the reliability of CVEs by providing a flexible and comprehensive vocabulary for describing the relationship with other standards and security references.

vFeed utilizes XML-based format output to describe vulnerabilities, it can be leveraged as input by various security tools / researchers as part of their vulnerability description. In fact, the standard syntax is very easy to interprete by humans and systems.

* Open security standards:
  - CVE (http://cve.mitre.org)
  - CWE (http://cwe.mitre.org)
  - CPE (http://cpe.mitre.org) 
  - OVAL (http://oval.mitre.org) 
  - CAPEC (http://capec.mitre.org) 
  - CVSS (http://www.first.org/cvss) 

* Vulnerability Assessment & Exploitation IDs (Metasploit, Saint Corporation, Nessus Scripts, Nmap, Exploit-DB, milw0rm)
* Vendors Security Alerts:
  - Microsoft MS
  - Mandriva
  - Redhat
  - Cisco
  - Sun
  - Gentoo
  - Ubuntu
  - And more


Key features
=================

* Built using open source technologies
* Fully downloadable SQLite local vulnerability database 
* Structured new XML format to describe vulnerabilities
* Based on major open standards CVE, CPE, CWE, CVSS..
* Support correlation with 3rd party security references (CVSS, OSVDB, OVAL…)
* Extended to support correlation with security assessment and patch vendors (Nessus, Exploit-DB, Redhat, Microsoft..)
* Simple & ready to use Python module with more than 30 methods

Target Audience
=================

* Penetration testers who want to analyze CVEs and gather extra information to help shape avenues to exploit vulnerabilities.
* Security auditors who want to report accurate information about findings. vFeed could be the best way to describe a CVE with attributes based on standards and 3rd party references as vendors or companies involved into standarization efforts.
* Security tools vendors / security open source developers who need to implement libraries to enumerate useful information about CVEs without wasting time to correlate and to create a proprietary database. vFeed is by far the best solution. Methods can be invoked from programs or scripts with a simple call.
* Any security hacker who is conducting researches and need a very fast and accurate way to enumerate available exploits or techniques to check a vulnerability


How to ?
==============

Run `vfeedcli.py` it's self-explanatory.
See the wiki for more details.
 

Latest release
==============

Beta v0.4.9
---------
* Added the support to Nmap NSE scripts (http://www.nmap.org)
* Added the support to D2 Elliot Web Exploitation Framework Exploits (http://www.d2sec.com/index.html)
* Now fully rely on OVAL Open Vulnerability Assessment Language definitions (https://oval.mitre.org/rep-data/5.10/org.mitre.oval/oval.xml)
* Updated the `get_oval` to return more information such title and class.
* Changed the stats methods names to `get_stats` and  `get_latest`
* To reflect this update, the following methods have been added:
 - `get_nmap` to enumerate Nmap NSE scripts. This function returns file name and category (ex: ./vfeedcli.py get_nmap CVE-2010-4345)
 - `get_d2` to enumerate D2 Elliot exploits. This function returns title and url link (ex: ./vfeedcli.py get_d2 CVE-2011-4106)

* vfeed.db the sqlite opensource cross linked vulnerability database fully regenerated to support the new changes


See changelog for details

