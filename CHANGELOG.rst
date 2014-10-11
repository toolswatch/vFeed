vFeed Changelog
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


Beta v0.4.8
---------
* Added a new class vFeedStats (vfeed\stats.py) to display vfeed.db statistics and the latest added CVEs (feature requested by Ryan Barnett from SpiderLabs).
* To reflect this update, the following methods have been added:
 - `stats` to enumerate vfeed.db global statistics such as total CVE, CPE, Nessus and more. This function returns the total for each reference
 - `latest_cve` to list the latest CVEs. 

Beta v0.4.7
---------
* Refactored the `vfeed_update.py` script as a separate class vFeedUpdate (vfeed\update.py). The method `update()` could be invoked to update the vulnerability database vFeed.db
* Added the support to HP (Hewlett-Packard) patch ids
* Added the support to BID - SecurityFocus ids
* Updated the Ubuntu, Redhat, CERT-VN mappers. Many new IDs have been added to vFeed.db
* To reflect the newest cross references, the following methods have been added:
 - `get_hp` to enumerate HP ids. This function returns the patches alonside with links
 - `get_bid` to list SecurityFocus Ids
 - `update` to download the newest vFeed.db database. python vfeedcli.py update will do the trick now 

* vfeed.db the sqlite opensource cross linked vulnerability database fully regenerated to support the new changes
* Documentation updated accordingly

Beta v0.4.6
---------
* Added the support to Suricata ET SID (http://suricata-ids.org/). When available, vFeed reports the mapping with Suricata ID, Attack title rule and class type
* Added the support to VMware IDs. 
* Updated the Gentoo GLSA mapper. Many new IDs have been added to vFeed.db
* Updated the Fedora mapper. Many new IDs have been added to vFeed.db
* To reflect the newest cross references, the following methods have been added: 
 - `get_suricata` to enumerate Suricata ID rules. This function returns Suricata SID, signature title and class type
 - `get_vmware` to list VMware patches

* vfeed.db the sqlite opensource cross linked vulnerability database fully regenerated to support the new changes
 
Beta v0.4.5
----------
* Added the support to CWE v2.5. Now, vFeed reports the newest CWE-id added to version 2.5. See here for more information http://cwe.mitre.org/data/reports/diff_reports/v2.4_v2.5.html
* Added the support to OWASP Top 2013. The method get_category() reports the appropriate OWASP ID. The method get_risk() also reports the categories of the attack as topAlert value.
* Better support of Microsoft Bulletins and KB.
* Extended the functions get_ms() and get_mskb() to report the Microsoft Title and URL.
* Added the support to Snort SID. A new function get_snort() is available. It returns snort sid, signature name and class type.
* Updated the vFeed XML export() function with a new attribute <defense>. The Snort IDs  could be leveraged to deploy detection capabilities.
* Fixed bug#24 https://github.com/toolswatch/vFeed/issues/24
* Fixed a bug with PCIstatus in get_risk(). Now PCIstatus is set as "Failed" when a topAlert is found
* Fixed a bug in get_risk(). The value are not set when the CVSS base is undefined
* Updated slightly get_risk() to also display CVSS scores. Top Vulnerability attribute took a sense. When all CVSS scores are set to 10, then Top Vulnerability is True.


Beta v0.4.0
-----------
* Refactored the `exportXML` method as a separate class vFeedXML (vfeed\exportxml.py). The method `export()` could be invoked to generate the appropriate vFeed XML format
* Changed methods name to something "pythonic compliant names" according to Andres Riancho (Thanks to David Mirza for python documentation). Format is now get_cve, get_cpe etc instead of the awful checkCVE, checkCPE ...(Issue Ref: https://github.com/toolswatch/vFeed/issues/13)
* Added the support to DISA/IAVM database (Information Assurance Vulnerability Alert) advisories from DoD-CERT. When available, the IAVM id and DISA VMSkey are reported
* Added the support to CERT-VN (CERT Vulnerability Notes Database (VU)). When available, the CERT-VU and Link are reported.
* Added the support to SCIP database effort from folks at www.scip.ch. The ids and link are reported (thanks to Marc Ruef @mruef for the help) 
* Added the support to OpenVAS (www.openvas.org). Whenever a reference exists, the ID, script file(s), family(s) and title are reported
* Added the support to Cisco Security Advisories (http://tools.cisco.com/security/center/publicationListing.x)
* Added the support to Ubuntu USN Security Notices (http://www.ubuntu.com/usn/)
* Added the support to Gentoo GLSA http://www.gentoo.org/security/en/glsa/
* Added the support to Fedora Security advisories (http://www.redhat.com/archives/fedora-announce-list/)
* To reflect the newest cross references, the following new methods have been added
 - `get_iavm` to check for DISA/IAVM ids associated with a CVE
 - `get_scip` to check for SCIP database ids
 - `get_certvn` to enumerate the CERT-VN ids
 - `get_openvas` to list the OpenVAS Vulnerability scanner scripts. It always classy to have both Nessus and OpenVAS scripts ;)
 - `get_cisco` to list cisco patchs
 - `get_ubuntu` to list ubuntu patchs
 - `get_gento`. You bet, it's for listing the Gentoo patchs
 - `get_fedora` to list the fedora patchs

* Despite the fact the OSVDB ids was already mapped with vFeed since the beginning, a new method `get_osvdb` has been added to enumerate them when available.
* Added `get_milw0rm` method even if the website is deprecated (for old time's sake)
* Introduced `vfeedcli.py` instead of awful script name `vFeed_Calls_1.py`. From now on,  vFeed CLI should  be used to get CVE attributes
* Slightly modified the `get_cve` keys to (summary, published and modified). Check the `vfeedcli.py` code source.
* vFeed XML format slightly modified. It's still easy to read and to parse.
* Minor bug fixed (when a CVE is missed, vFeed exits)
* vfeed.db regenerated to support the newest changes
* Documentation should be updated the reflect the major methods name changes


Beta v0.3.9
-----------
* Added the support of Metasploit Ids. Now vFeed reports msf exploit id, link to file and title
* Added the support of CAPEC. When the reference exists, the CAPEC id and link are reported accordingly with its associated CWE
* checkCWE extended to support the CWE title. Sometimes, it's comfortable to deal with human words than ids ;)
* checkRISK extended to support Top Categories as CWE/SANS 2011, OWASP 2010 etc. Whenever the CVE is flagged in the some specific categories (see api.py at _isTopAlert), 
the topAlert value is filled with categories name such as OWASP Top Ten 2010 Category A1 - Injection or 2011 Top 25 - Insecure Interaction Between Components
* checkCVSS extended to support the CVSS Vector. 
* To reflect the newest cross references, 3 new methods have been added
  - checkMSF to check for Metasploit sploits or plugins
  - checkCAPEC to enumerate the CWE associated (and indirectly CVE) CAPEC ids
  - checkCATEGORY to list the whole Top Categories associated with CWE and indirectly CVE. This method is useful if topAlert doesnt report any known Top List.
  - Updated checkRISK, checkCWE and checkCVSS
  - updated exportXML to reflect the changes.
  
* vfeed.db regenerated from scratch to support the newest changes. 
* Documentation as usual in progress.  


Beta v0.3.6
-----------
* Refactoring as a first step towards having the vfeed module in pypi (andres riancho)
* PEP8 compatible code (at least what autopep8 can do) (andres riancho)
* README format is now RST (andres riancho)
* Bug fixes (andres riancho)
* Global vfeed.db update with latest CVEs, Redhat OVAL, SaintExploit, Nessus Scripts ..... 

Beta v0.3.5
-----------

* Extended the checkREDHAT method
  - Added the support of Redhat OVAL ids reference. Now, vFeed reports more accurate Redhat Patchs with associated Redhat OVAL ids 
  - Added the support of Redhat Bugzilla Ids and advisory issue date

* Added the support of Debian ids. vFeed now reports DSA as patch
* Added the support of Mandriva ids.
* Extended Exploitation Checks to support Saint Corporation Exploits. If available, title, link to exploit file are reported
* To reflect the newest cross references, 3 new methods have been added 
  - checkREDHAT extended to support Redhat OVAL, Bugzilla ids more redhat patchs ids.
  - checkDEBIAN to check for debian patchs
  - checkMANDRIVA to check for mandrake patchs
  - checkSAINT to check for Saint corporation exploits 

* Fixed a small bug in checkRISK() (thanks to Ronald Bister https://github.com/savon-noir)
* Updating wiki documentation in progress
 
Beta v0.3
---------

* Rewrite vFeedApi.py as a class (added _init_db() method with sql query sanitization)
* Added a class vFeedInfo to return variables and global configuration
* Added a config.py module.
* Updated the "update.py". Now verifies if a new db is available (support of checksum)
* Renamed method checkReferences into checkREF()
* Updated the sample scripts (vFeedAPI_calls_1 and _2) to reflect the changes
* documentation update (always in progress) and will be mainly delivered via vfeed github wiki.

Beta v0.2
---------

* moved project to github
* added an updater.py to download the vFeed vulnerability database

Beta v0.1
---------
* initial release 
* read documentation