#!/bin/bash

read -p "Enter Target IP/Domain: " TARGET

nmap --script=ftp-anon.nse "$TARGET" 
nmap --script=ftp-bounce.nse "$TARGET" 
nmap --script=ftp-brute.nse "$TARGET" 
nmap --script=ftp-libopie.nse "$TARGET" 
nmap --script=ftp-proftpd-backdoor.nse "$TARGET" 
nmap --script=ftp-syst.nse "$TARGET" 
nmap --script=ftp-vsftpd-backdoor.nse "$TARGET" 
nmap --script=ftp-vuln-cve2010-4221.nse "$TARGET" 
nmap --script=snmp-win32-software.nse "$TARGET" 
nmap --script=tftp-enum.nse "$TARGET" 
nmap --script=tftp-version.nse "$TARGET" 
