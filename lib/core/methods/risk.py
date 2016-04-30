#!/usr/bin/env python
# Copyright (C) 2016 ToolsWatch.org
# This file is part of vFeed Correlated Threat & Vulnerability Community Database API Parser - http://www.toolswatch.org
# See the file 'LICENSE' for copying permission.
import json
from lib.common.database import Database
from lib.core.methods.info import CveInfo


class CveRisk(object):
    def __init__(self, cve_id):
        self.cve_id = cve_id.upper()
        (self.cur, self.query) = Database(self.cve_id).db_init()
        self.data = Database(self.cve_id, self.cur, self.query).check_cve()

    def get_cvss(self):
        """ CVSS  method
        :return: JSON response with CVSS scores
        """
        self.cvss = []
        item = {'base': str(self.data[4]), 'impact': str(self.data[5]), 'exploit': str(self.data[6]),
                'access vector': str(self.data[7]), 'access complexity': str(self.data[8]),
                'authentication': str(self.data[9]), 'confidentiality impact': str(self.data[10]),
                'integrity impact': str(self.data[11]), 'availability impact': str(self.data[12])}
        self.cvss.append(item)

        return json.dumps(self.cvss, indent=4, sort_keys=True)

    def get_severity(self):
        """ Severity Method
        :return: JSON response with Severity level, Top categories ...
        """

        self.severity = []
        self.cvss = self.get_cvss()
        cvss_data = json.loads(self.cvss)

        self.top_alert = self.top_alert()
        self.top_vulnerable = False

        if cvss_data[0]["base"] == "not_defined":
            self.level = "Not Defined"
            self.top_vulnerable = "Not Defined"
        elif cvss_data[0]["base"] == "10.0" and cvss_data[0]["exploit"] == "10.0" and cvss_data[0]["impact"] == "10.0":
            self.level = "High"
            self.top_vulnerable = True
        elif cvss_data[0]["base"] >= "7.0":
            self.level = "High"
        elif "4.0" <= cvss_data[0]["base"] <= "6.9":
            self.level = "Moderate"
        elif "0.1" <= cvss_data[0]["base"] <= "3.9":
            self.level = "Low"

        item = {'severity': self.level,
                'Top vulnerable': self.top_vulnerable,
                'Top alert': self.top_alert,
                'CVSS v2': cvss_data
                }
        self.severity.append(item)

        return json.dumps(self.severity, indent=4)

    def top_alert(self):

        """
        Returning:  top list of CWEs such as in  CWE/SANS 2011, OWASP 2010, OWASP 2013....

        """

        self.top_alert = []
        self.category = CveInfo(self.cve_id).get_category()

        if json.loads(self.category) is None:
            return False

        self.category = json.loads(self.category)
        self.top_category = ['CWE-929', 'CWE-930', 'CWE-931', 'CWE-932', 'CWE-933', 'CWE-934', 'CWE-935', 'CWE-936',
                             'CWE-937', 'CWE-938', 'CWE-810', 'CWE-811', 'CWE-812', 'CWE-813', 'CWE-814', 'CWE-815',
                             'CWE-816', 'CWE-817', 'CWE-818', 'CWE-819', 'CWE-864', 'CWE-865', 'CWE-691']

        """

        CWE-864 --> 2011 Top 25 - Insecure Interaction Between Components
        CWE-865 --> 2011 Top 25 - Risky Resource Management
        CWE-691 --> Insufficient Control Flow Management
        CWE-810 --> OWASP Top Ten 2010 Category A1 - Injection
        CWE-811 --> OWASP Top Ten 2010 Category A2 - Cross-Site Scripting (XSS)
        CWE-812 --> OWASP Top Ten 2010 Category A3 - Broken Authentication and Session Management
        CWE-813 --> OWASP Top Ten 2010 Category A4 - Insecure Direct Object References
        CWE-814 --> OWASP Top Ten 2010 Category A5 - Cross Site Request Forgery (CSRF)
        CWE-815 --> OWASP Top Ten 2010 Category A6 - Security Misconfiguration
        CWE-816 --> OWASP Top Ten 2010 Category A7 - Insecure Cryptographic Storage
        CWE-817 --> OWASP Top Ten 2010 Category A8 - Failure to Restrict URL Access
        CWE-818 --> OWASP Top Ten 2010 Category A9 - Insufficient Transport Layer Protection
        CWE-819 --> OWASP Top Ten 2010 Category A10 - Unvalidated Redirects and Forwards
        CWE-929 --> OWASP Top Ten 2013 Category A1 - Injection
        CWE-930 --> OWASP Top Ten 2013 Category A2 - Broken Authentication and Session Management
        CWE-931 --> OWASP Top Ten 2013 Category A3 - Cross-Site Scripting (XSS)
        CWE-932 --> OWASP Top Ten 2013 Category A4 - Insecure Direct Object References
        CWE-933 --> OWASP Top Ten 2013 Category A5 - Security Misconfiguration
        CWE-934 --> OWASP Top Ten 2013 Category A6 - Sensitive Data Exposure
        CWE-935 --> OWASP Top Ten 2013 Category A7 - Missing Function Level Access Control
        CWE-936 --> OWASP Top Ten 2013 Category A8 - Cross-Site Request Forgery (CSRF)
        CWE-937 --> OWASP Top Ten 2013 Category A9 - Using Components with Known Vulnerabilities
        CWE-938 --> OWASP Top Ten 2013 Category A10 - Unvalidated Redirects and Forwards

        """

        for self_cat in self.top_category:
            for item in self.category:
                if item.get("id") == self_cat:
                    item = {"id": item.get("id"), "title": item.get("title")}
                    self.top_alert.append(item)

        if self.top_alert:
            return self.top_alert
        else:
            return False
