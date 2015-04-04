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

Standard Compatibility
==============

vFeed is now officially registered as CVE-Compatible Product by the Mitre Corp (https://cve.mitre.org/compatible/compatible.html)

Latest release
==============

Beta v0.5.0
---------
* Added a new class search.py. Now it is possible to search for CPE associated CVEs. Check the full documentation
* Added the support to CWE v2.8 with the addition to 58 nodes. Check here the full changelog http://cwe.mitre.org/data/reports/diff_reports/v2.7_v2.8.html
* Updated the `vfeed_calls_samples.py` with example to use update and search methods within your python scripts.
* Fixed an incoherence in the ExploitDB. In some cases, the exploit file is filled with http://www.exploit-db.com/download/Id_Exploit instead of blank.
*  Fixed variable naming in uncompress() try statement in the `update` class (thanks to Jason https://github.com/Cashiuus)
* To reflect this update, the following methods have been added:
 - `search` to enumerate CVE and CPEs information (ex: ./vfeedcli.py search CVE-2010-4345 or ./vfeedcli.py search cpe:/a:openssl:openssl:1.0.1). Refer to documentation https://github.com/toolswatch/vFeed/wiki/%5B2%5D-Usage section "searching for occurrences"

* vfeed.db the sqlite opensource cross linked vulnerability database fully regenerated to support the new changes
* The documentation updated https://github.com/toolswatch/vFeed/wiki/


See changelog for details

