.headers on
.mode csv

.once vFeed/csv_exports/cve_cpe.csv
SELECT * FROM cve_cpe;


.once vFeed/csv_exports/nvd_db.csv
SELECT cveid, date_published, date_modified, summary, cvss_base, cvss_impact, cvss_exploit, cvss_access_vector, cvss_access_complexity, cvss_authentication, cvss_confidentiality_impact, cvss_integrity_impact, cvss_availability_impact FROM nvd_db;


.once vFeed/csv_exports/cve_cwe.csv
SELECT * FROM cve_cwe;


.once vFeed/csv_exports/cve_reference.csv
SELECT * FROM cve_reference;


.once vFeed/csv_exports/cwe_capec.csv
SELECT * FROM cwe_capec;


.once vFeed/csv_exports/cwe_category.csv
SELECT * FROM cwe_category;


.once vFeed/csv_exports/cwe_db.csv
SELECT * FROM cwe_db;


.once vFeed/csv_exports/map_cve_aixapar.csv
SELECT * FROM map_cve_aixapar;


.once vFeed/csv_exports/map_cve_bid.csv
SELECT * FROM map_cve_bid;


.once vFeed/csv_exports/map_cve_certvn.csv
SELECT * FROM map_cve_certvn;


.once vFeed/csv_exports/map_cve_cisco.csv
SELECT * FROM map_cve_cisco;


.once vFeed/csv_exports/map_cve_d2.csv
SELECT * FROM map_cve_d2;


.once vFeed/csv_exports/map_cve_debian.csv
SELECT * FROM map_cve_debian;


.once vFeed/csv_exports/map_cve_exploitdb.csv
SELECT * FROM map_cve_exploitdb;


.once vFeed/csv_exports/map_cve_fedora.csv
SELECT * FROM map_cve_fedora;


.once vFeed/csv_exports/map_cve_oval.csv
SELECT * FROM map_cve_oval;


.once vFeed/csv_exports/map_cve_gentoo.csv
SELECT * FROM map_cve_gentoo;


.once vFeed/csv_exports/map_cve_redhat.csv
SELECT * FROM map_cve_redhat;


.once vFeed/csv_exports/map_cve_hp.csv
SELECT * FROM map_cve_hp;


.once vFeed/csv_exports/map_cve_saint.csv
SELECT * FROM map_cve_saint;


.once vFeed/csv_exports/map_cve_iavm.csv
SELECT * FROM map_cve_iavm;


.once vFeed/csv_exports/map_cve_scip.csv
SELECT * FROM map_cve_scip;


.once vFeed/csv_exports/map_cve_mandriva.csv
SELECT * FROM map_cve_mandriva;


.once vFeed/csv_exports/map_cve_snort.csv
SELECT * FROM map_cve_snort;


.once vFeed/csv_exports/map_cve_milw0rm.csv
SELECT * FROM map_cve_milw0rm;


.once vFeed/csv_exports/map_cve_suricata.csv
SELECT * FROM map_cve_suricata;


.once vFeed/csv_exports/map_cve_ms.csv
SELECT * FROM map_cve_ms;


.once vFeed/csv_exports/map_cve_suse.csv
SELECT * FROM map_cve_suse;


.once vFeed/csv_exports/map_cve_msf.csv
SELECT * FROM map_cve_msf;


.once vFeed/csv_exports/map_cve_ubuntu.csv
SELECT * FROM map_cve_ubuntu;


.once vFeed/csv_exports/map_cve_mskb.csv
SELECT * FROM map_cve_mskb;


.once vFeed/csv_exports/map_cve_vmware.csv
SELECT * FROM map_cve_vmware;


.once vFeed/csv_exports/map_cve_nessus.csv
SELECT * FROM map_cve_nessus;


.once vFeed/csv_exports/map_redhat_bugzilla.csv
SELECT * FROM map_redhat_bugzilla;


.once vFeed/csv_exports/map_cve_nmap.csv
SELECT * FROM map_cve_nmap;


.once vFeed/csv_exports/map_cve_openvas.csv
SELECT * FROM map_cve_openvas;


.once vFeed/csv_exports/map_cve_osvdb.csv
SELECT * FROM map_cve_osvdb;


.once vFeed/csv_exports/stat_vfeed_kpi.csv
SELECT * FROM stat_vfeed_kpi;


.once vFeed/csv_exports/stat_new_cve.csv
SELECT * FROM stat_new_cve;
