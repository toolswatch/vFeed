vFeed Python API & vFeed.db The Correlated Community Vulnerability and Threat Database
=========================================================
![vFeed](http://www.toolswatch.org/wp-content/uploads/2015/10/vfeed-e1443794779894.png)

**vFeed Framework** is a CVE, CWE and OVAL Compatible naming scheme concept that provides extra structured detailed third-party references and technical characteristics for a CVE entry through an extensible XML/JSON schema.
It also improves the reliability of CVEs by providing a flexible and comprehensive vocabulary for describing the relationship with other standards and security references.

vFeed utilizes XML-based / JSON-based format outputs to describe in detail vulnerabilities.
They can be leveraged as input by security researchers, practitioners and tools as part of their vulnerability description. In fact, the standard syntax is easy to interpret by humans and systems.

The associated **vFeed.db (The Correlated Vulnerability and Threat Database)** is a detective and preventive security information repository used for gathering vulnerability and mitigation data from scattered internet sources into an unified database.

* Open security standards:
    * [CVE](http://cve.mitre.org)
    * [CWE](http://cwe.mitre.org)
    * [CPE](http://cpe.mitre.org)
    * [OVAL](http://oval.mitre.org)
    * [CAPEC](http://capec.mitre.org)
    * [CVSS](http://www.first.org/cvss)

* Vulnerability Assessment & Exploitation IDs (Metasploit, Saint Corporation, Nessus Scripts, Nmap, Exploit-DB, milw0rm)
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

* Registered as CVE, CWE and OVAL Compatible by the Mitre Corporation
* Built using open source technologies
* Rely on main Open Standards CVE, CPE, CWE, CAPEC, CVSS etc
* Downloadable SQLite Community Correlated Vulnerability and Threat Database
* New Structured XML format to describe vulnerability
* Support correlation with 3rd party security references IAVA, OSVDB, OVAL etc
* Support correlation with security assessment and patch vendors (Nessus, Exploit-DB, Redhat, Microsoft..)
* Simple and ready-to-use API Python methods

Target Audience
=================

* Penetration testers who want to analyze CVEs and gather extra information to help shape avenues to exploit vulnerabilities.
* Security auditors who want to report accurate information about findings. vFeed could be the best way to describe a CVE with attributes based on standards and 3rd party references as vendors or companies involved into standarization efforts.
* Security tools vendors / security open source developers who need to implement libraries to enumerate useful information about CVEs without wasting time to correlate and to create a proprietary database. vFeed is by far the best solution. Methods can be invoked from programs or scripts with a simple call.
* Any security hacker who is conducting researches and need a very fast and accurate way to enumerate available exploits or techniques to check a vulnerability


How to ?
==============

Run `vfeedcli.py -h` for help.
Refer to the [wiki](https://github.com/toolswatch/vFeed/wiki/) page for a detailed documentation.


Latest release
==============

0.6.0
---------
* Reviewed and re-wrote the code to be as much as possible PEP8 compliant
* Introduced a new simple vFeed menu with the following options:
    * --method: Digs into the database and enumerate information related to CVE. See (--list)
    * --list: Lists the available --method functions. You can refer to the wiki documentation for more information
    * --export : Exports metadata to either JSON or XML formats
    * --stats : Displays the vFeed.db statistics
    * --search: Simple vFeed search utility. It supports CVE, CPE, CWE, OVAL and free text
    * --update: To update the vFeed.db Correlated Vulnerability Database.
    * --banner: Displays vFeed banners. Dont ask me. It is useless :)
* Refactored the main vFeed class `api.py` into small dedicated classes:
    * `info.py`: Used to render information about CVE alongside other open standards (CWE, CPE, CAPEC).
    * `ref.py`: Can be leveraged to get information about references and cross-linked sources (IAVM, SCIP..)
    * `risk.py`: Used to display the CVSS v2 and severity.
    * `patches.py`: Mostly used to enumerate hotfixes from 3rd party vendors such as Microsoft, Redhat, Suse etc
    * `scanners.py` : Leveraged to list information about scanners scripts related to CVEs such as Nessus, OpenVAS ..
    * `exploit.py` : Used to list information about exploits PoC related to CVEs such as Metasploit, Exploit-DB ..
    * `rules.py` : Can be leveraged to display the IDS/IPS rules to prevent from the attack such as Snort or Suricata
    * `json_dump.py` : This class will generate a detailed CVE JSON output.
* vFeed now returns JSON responses. It will be much easier to integrate with 3rd party utilities and software.
* Added the support of CWE, OVAL and free text to `search.py` class.
* Added URL links to the references (CVE, CWE, CAPEC, 3rd party references ..)
* Changed name of `get_risk` to `get_severity`
* Exported JSON/XML files are moved to the export repository.
* Added `api_calls.py` API calls sample to demonstrate how easy to use vFeed from within your code.
* Deprecated the value of "PCI Compliance" from `risk.py` class. This will be supported later.
* Deprecated the method `get_milw0rm` as the source does not longer exist
* Todo : The XML export will be added later.
* The documentation updated. Visit [Documentation Page](https://github.com/toolswatch/vFeed/wiki/)

See [changelog](https://github.com/toolswatch/vFeed/blob/master/CHANGELOG.md) for more details

Database migrations
===================

Before migrations
-----------------
  * Please ensure that the cloned repository is at user's home directory
    * Instance: Linux `git clone https://github.com/toolswatch/vFeed.git /home/<username>/vFeed`
    * Instance: Windows `git clone https://github.com/toolswatch/vFeed.gitc:\users\<usersname>\vFeed`
    * Replace <username> with current username

Mongo migrations
----------------
* To migrate vfeed SQLite Database to MongoDB
  * Ensure that MongoDB is installed on local server
    * If MongoDB is a remote server configure `mongo.conf` file in the migrationScripts directory. The default is `localhost:27017` without authentication or SSL.
  * Replace <username> with current username
    * run `python /home/<username>/vFeed/migrationScripts/mongomigration.py` on Linux
    * run `python c:\users\<username>\vFeed\migrationScripts\mongomigration.py` on Windows

Meteor UI
---------

* To Get started with Meteor UI 
  * Install Meteor by typing `curl https://install.meteor.com/ | sh` in a Linux or OS X Terminal
  * For Windows machines, Visit `https://www.meteor.com/install`
  * Navigate to `vFeed` directory and type `meteor update`
  * Alternatively, `meteor update <packagename>` to update a package
  * The UI is currently a SPA (Single Page Application).
  * The search field is available and is not yet implemented for searching `vfeed database`
  * Meteor applications use mongodb by default. Here is a cautious step:
      1. Inside the `migrationScripts` directory, edit `mongo.conf` to port 3001
      2. From a seperate terminal type `meteor mongo`. (At this point, ensure the meteor app is already running to interact with meteor).
      3. Run the mongo migration script `python mongomigration.py` in the `migrationScripts` directory

      Explanation:
      ============
      * MongoDB runs on port 27017 by default.
      * Meteor's mongo runs on port 3001
      * By changing migration script to point to 3001, when meteor app is running, metoeor application's database gets vFeed tables.
