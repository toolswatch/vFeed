# vfeed.sh - vFeed Menu
# Version: 0.2 (20131126)
# Created By: Glenn 'devalias' Grant (http://devalias.net)
# License: The MIT License (MIT) - Copyright (c) 2013 Glenn 'devalias' Grant (see http://choosealicense.com/licenses/mit/ for full license text)
# vFeed URL: https://github.com/toolswatch/vfeed
BANNER="
==============================================================================================
vfeed.sh - vFeed Menu v0.2 (20131126) by Glenn 'devalias' Grant (http://devalias.net)
==============================================================================================
"

cd ~/pentest/vFeed

# Check parameters
if [ "$#" -ne 1 ]
  then
    echo "$BANNER"
    echo "[usage] vfeed <CVE id>"
    echo " "
    exit
fi

CVEID="$1"

echo "$BANNER"
select MENUOPTION in Information References Risk Patches Assessment Defense Exploitation CommandLineInterface Update About Exit
do
  case $MENUOPTION in
    Information)
      # Information  ==> get_cve | get_cpe | get_cwe | get_capec | get_category | get_iavm
      echo "=============================================================================================="
      echo "Information $CVEID (get_cve | get_cpe | get_cwe | get_capec | get_category | get_iavm)"
      echo "=============================================================================================="
      python vfeedcli.py get_cve $CVEID
      echo
      python vfeedcli.py get_cpe $CVEID
      echo
      python vfeedcli.py get_cwe $CVEID
      echo
      python vfeedcli.py get_capec $CVEID
      echo
      python vfeedcli.py get_category $CVEID
      echo
      python vfeedcli.py get_iavm $CVEID
      echo
      ;;
    References)
      # References   ==> get_refs | get_scip | get_osvdb | get_certvn
      echo "=============================================================================================="
      echo "References $CVEID (get_refs | get_scip | get_osvdb | get_certvn)"
      echo "=============================================================================================="
      python vfeedcli.py get_refs $CVEID
      echo
      python vfeedcli.py get_scip $CVEID
      echo
      python vfeedcli.py get_osvdb $CVEID
      echo
      python vfeedcli.py get_certvn $CVEID
      echo
      ;;
    Risk)
      # Risk         ==> get_risk | get_cvss
      echo "=============================================================================================="
      echo "Risk $CVEID (get_risk | get_cvss)"
      echo "=============================================================================================="
      python vfeedcli.py get_risk $CVEID
      echo
      python vfeedcli.py get_cvss $CVEID
      echo
      ;;
    Patches)
      # Patchs       ==> get_ms | get_kb | get_aixapar | get_redhat | get_suse | get_debian
      # Patchs       ==> get_mandriva | get_cisco | get_ubuntu | get_gentoo | get_fedora | get_vmware
      echo "=============================================================================================="
      echo "Patches $CVEID (get_ms | get_kb | get_aixapar | get_redhat | get_suse | get_debian | get_mandriva | get_cisco | get_ubuntu | get_gentoo | get_fedora | get_vmware)"
      echo "=============================================================================================="
      python vfeedcli.py get_ms $CVEID
      echo
      python vfeedcli.py get_kb $CVEID
      echo
      python vfeedcli.py get_aixapar $CVEID
      echo
      python vfeedcli.py get_redhat $CVEID
      echo
      python vfeedcli.py get_suse $CVEID
      echo
      python vfeedcli.py get_debian $CVEID
      echo
      python vfeedcli.py get_mandriva $CVEID
      echo
      python vfeedcli.py get_cisco $CVEID
      echo
      python vfeedcli.py get_ubuntu $CVEID
      echo
      python vfeedcli.py get_gentoo $CVEID
      echo
      python vfeedcli.py get_fedora $CVEID
      echo
      python vfeedcli.py get_vmware $CVEID
      echo
      ;;
    Assessment)
      # Assessment   ==> get_oval | get_nessus | get_openvas
      echo "=============================================================================================="
      echo "Assessment $CVEID (get_oval | get_nessus | get_openvas)"
      echo "=============================================================================================="
      python vfeedcli.py get_oval $CVEID
      echo
      python vfeedcli.py get_nessus $CVEID
      echo
      python vfeedcli.py get_openvas $CVEID
      echo
      ;;
    Defense)
      # Defense      ==> get_snort | get_suricata
      echo "=============================================================================================="
      echo "Defense $CVEID (get_snort | get_suricata)"
      echo "=============================================================================================="
      python vfeedcli.py get_snort $CVEID
      echo
      python vfeedcli.py get_suricata $CVEID
      echo
      ;;
    Exploitation)
      # Exploitation ==> get_milw0rm | get_edb | get_saint | get_msf
      echo "=============================================================================================="
      echo "Exploitation $CVEID (get_milw0rm | get_edb | get_saint | get_msf)"
      echo "=============================================================================================="
      python vfeedcli.py get_milw0rm $CVEID
      echo
      python vfeedcli.py get_edb $CVEID
      echo
      python vfeedcli.py get_saint $CVEID
      echo
      python vfeedcli.py get_msf $CVEID
      echo
      ;;
    CommandLineInterface)
      echo "[usage]: vfeedcli <API Method> <CVE id>"
      echo
      break
      ;;
    Update)
      echo "=============================================================================================="
      echo "Update"
      echo "=============================================================================================="
      python vfeed_update.py
      ;;
    About)
      echo "$BANNER"
      echo
    ;;
    Exit)
      echo "Exiting.."
      echo
      break
      ;;
    *)
      echo "ERROR: Invalid Selection."
      echo
      ;;
  esac
done
