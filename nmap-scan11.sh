#!/usr/bin/env bash

# ==========================================
# Nmap Service Scanner
# ==========================================

# ---------- Root check ----------
if [[ $EUID -ne 0 ]]; then
    echo "[!] This script must be run as root."
    echo "[*] Re-running with sudo..."
    exec sudo bash "$0" "$@"
fi

echo "=========================================="
echo "        NMAP SERVICE SCANNER"
echo "=========================================="

# ---------- Target input ----------
read -rp "Enter target IP/hostname: " TARGET

if [[ -z "$TARGET" ]]; then
    echo "[!] Target cannot be empty."
    exit 1
fi

# ---------- Check Nmap ----------
if ! command -v nmap >/dev/null 2>&1; then
    echo "[!] Nmap is not installed."
    exit 1
fi

echo
echo "Target: $TARGET"
echo

# ---------- Scan menu ----------
while true; do

    echo "=========================================="
    echo "             SELECT SCAN"
    echo "=========================================="

    options=(
        "HTTP"
        "SMTP"
        "FTP"
        "SSH"
        "LDAP"
        "GIT"
        "Exit"
    )

    select SERVICE in "${options[@]}"; do
        case "$SERVICE" in

            "HTTP")
                echo
                echo "[*] Running HTTP scan..."
                nmap --script=http-adobe-coldfusion-apsa1301.nse "$TARGET" \
                    | tee http-scan.txt

                echo "[+] Output saved to http-scan.txt"
                break
                ;;

            "FTP")
                echo
                echo "[*] Running FTP scan..."
                nmap --script=ftp-scan.nse "$TARGET" \
                    | tee ftp-scan.txt

                echo "[+] Output saved to ftp-scan.txt"
                break
                ;;

            "SSH")
                echo
                echo "[*] Running SSH scan..."

# Add the SSH NSE scripts you want to use here.
nmap --script=ssh2-enum-algos "$TARGET" \
nmap --script=http-adobe-coldfusion-apsa1301.nse "$TARGET" \
nmap --script=http-affiliate-id.nse "$TARGET" \
nmap --script=http-apache-negotiation.nse "$TARGET" \
nmap --script=http-apache-server-status.nse "$TARGET" \
nmap --script=http-aspnet-debug.nse "$TARGET" \
nmap --script=http-auth-finder.nse "$TARGET" \
nmap --script=http-auth.nse "$TARGET" \
nmap --script=http-avaya-ipoffice-users.nse "$TARGET" \
nmap --script=http-awstatstotals-exec.nse "$TARGET" \
nmap --script=http-axis2-dir-traversal.nse "$TARGET" \
nmap --script=http-backup-finder.nse "$TARGET" \
nmap --script=http-barracuda-dir-traversal.nse "$TARGET" \
nmap --script=http-bigip-cookie.nse "$TARGET" \
nmap --script=http-brute.nse "$TARGET" \
nmap --script=http-cakephp-version.nse "$TARGET" \
nmap --script=http-chrono.nse "$TARGET" \
nmap --script=http-cisco-anyconnect.nse "$TARGET" \
nmap --script=http-coldfusion-subzero.nse "$TARGET" \
nmap --script=http-comments-displayer.nse "$TARGET" \
nmap --script=http-config-backup.nse "$TARGET" \
nmap --script=http-cookie-flags.nse "$TARGET" \
nmap --script=http-cors.nse "$TARGET" \
nmap --script=http-cross-domain-policy.nse "$TARGET" \
nmap --script=http-csrf.nse "$TARGET" \
nmap --script=http-date.nse "$TARGET" \
nmap --script=http-default-accounts.nse "$TARGET" \
nmap --script=http-devframework.nse "$TARGET" \
nmap --script=http-dlink-backdoor.nse "$TARGET" \
nmap --script=http-dombased-xss.nse "$TARGET" \
nmap --script=http-domino-enum-passwords.nse "$TARGET" \
nmap --script=http-drupal-enum.nse "$TARGET" \
nmap --script=http-drupal-enum-users.nse "$TARGET" \
nmap --script=http-enum.nse "$TARGET" \
nmap --script=http-errors.nse "$TARGET" \
nmap --script=http-exif-spider.nse "$TARGET" \
nmap --script=http-favicon.nse "$TARGET" \
nmap --script=http-feed.nse "$TARGET" \
nmap --script=http-fetch.nse "$TARGET" \
nmap --script=http-fileupload-exploiter.nse "$TARGET" \
nmap --script=http-form-brute.nse "$TARGET" \
nmap --script=http-form-fuzzer.nse "$TARGET" \
nmap --script=http-frontpage-login.nse "$TARGET" \
nmap --script=http-generator.nse "$TARGET" \
nmap --script=http-git.nse "$TARGET" \
nmap --script=http-gitweb-projects-enum.nse "$TARGET" \
nmap --script=http-google-malware.nse "$TARGET" \
nmap --script=http-grep.nse "$TARGET" \
nmap --script=http-headers.nse "$TARGET" \
nmap --script=http-hp-ilo-info.nse "$TARGET" \
nmap --script=http-huawei-hg5xx-vuln.nse "$TARGET" \
nmap --script=http-icloud-findmyiphone.nse "$TARGET" \
nmap --script=http-icloud-sendmsg.nse "$TARGET" \
nmap --script=http-iis-short-name-brute.nse "$TARGET" \
nmap --script=http-iis-webdav-vuln.nse "$TARGET" \
nmap --script=http-internal-ip-disclosure.nse "$TARGET" \
nmap --script=http-joomla-brute.nse "$TARGET" \
nmap --script=http-jsonp-detection.nse "$TARGET" \
nmap --script=http-litespeed-sourcecode-download.nse "$TARGET" \
nmap --script=http-ls.nse "$TARGET" \
nmap --script=http-majordomo2-dir-traversal.nse "$TARGET" \
nmap --script=http-malware-host.nse "$TARGET" \
nmap --script=http-mcmp.nse "$TARGET" \
nmap --script=http-methods.nse "$TARGET" \
nmap --script=http-method-tamper.nse "$TARGET" \
nmap --script=http-mobileversion-checker.nse "$TARGET" \
nmap --script=http-ntlm-info.nse "$TARGET" \
nmap --script=http-open-proxy.nse "$TARGET" \
nmap --script=http-open-redirect.nse "$TARGET" \
nmap --script=http-passwd.nse "$TARGET" \
nmap --script=http-phpmyadmin-dir-traversal.nse "$TARGET" \
nmap --script=http-phpself-xss.nse "$TARGET" \
nmap --script=http-php-version.nse "$TARGET" \
nmap --script=http-proxy-brute.nse "$TARGET" \
nmap --script=http-put.nse "$TARGET" \
nmap --script=http-qnap-nas-info.nse "$TARGET" \
nmap --script=http-referer-checker.nse "$TARGET" \
nmap --script=http-rfi-spider.nse "$TARGET" \
nmap --script=http-robots.txt.nse "$TARGET" \
nmap --script=http-robtex-reverse-ip.nse "$TARGET" \
nmap --script=http-robtex-shared-ns.nse "$TARGET" \
nmap --script=http-sap-netweaver-leak.nse "$TARGET" \
nmap --script=http-security-headers.nse "$TARGET" \
nmap --script=http-server-header.nse "$TARGET" \
nmap --script=http-shellshock.nse "$TARGET" \
nmap --script=http-sitemap-generator.nse "$TARGET" \
nmap --script=http-slowloris-check.nse "$TARGET" \
nmap --script=http-slowloris.nse "$TARGET" \
nmap --script=http-sql-injection.nse "$TARGET" \
nmap --script=https-redirect.nse "$TARGET" \
nmap --script=http-stored-xss.nse "$TARGET" \
nmap --script=http-svn-enum.nse "$TARGET" \
nmap --script=http-svn-info.nse "$TARGET" \
nmap --script=http-title.nse "$TARGET" \
nmap --script=http-tplink-dir-traversal.nse "$TARGET" \
nmap --script=http-trace.nse "$TARGET" \
nmap --script=http-traceroute.nse "$TARGET" \
nmap --script=http-trane-info.nse "$TARGET" \
nmap --script=http-unsafe-output-escaping.nse "$TARGET" \
nmap --script=http-useragent-tester.nse "$TARGET" \
nmap --script=http-userdir-enum.nse "$TARGET" \
nmap --script=http-vhosts.nse "$TARGET" \
nmap --script=http-virustotal.nse "$TARGET" \
nmap --script=http-vlcstreamer-ls.nse "$TARGET" \
nmap --script=http-vmware-path-vuln.nse "$TARGET" \
nmap --script=http-vuln-cve2006-3392.nse "$TARGET" \
nmap --script=http-vuln-cve2009-3960.nse "$TARGET" \
nmap --script=http-vuln-cve2010-0738.nse "$TARGET" \
nmap --script=http-vuln-cve2010-2861.nse "$TARGET" \
nmap --script=http-vuln-cve2011-3192.nse "$TARGET" \
nmap --script=http-vuln-cve2011-3368.nse "$TARGET" \
nmap --script=http-vuln-cve2012-1823.nse "$TARGET" \
nmap --script=http-vuln-cve2013-0156.nse "$TARGET" \
nmap --script=http-vuln-cve2013-6786.nse "$TARGET" \
nmap --script=http-vuln-cve2013-7091.nse "$TARGET" \
nmap --script=http-vuln-cve2014-2126.nse "$TARGET" \
nmap --script=http-vuln-cve2014-2127.nse "$TARGET" \
nmap --script=http-vuln-cve2014-2128.nse "$TARGET" \
nmap --script=http-vuln-cve2014-2129.nse "$TARGET" \
nmap --script=http-vuln-cve2014-3704.nse "$TARGET" \
nmap --script=http-vuln-cve2014-8877.nse "$TARGET" \
nmap --script=http-vuln-cve2015-1427.nse "$TARGET" \
nmap --script=http-vuln-cve2015-1635.nse "$TARGET" \
nmap --script=http-vuln-cve2017-1001000.nse "$TARGET" \
nmap --script=http-vuln-cve2017-5638.nse "$TARGET" \
nmap --script=http-vuln-cve2017-5689.nse "$TARGET" \
nmap --script=http-vuln-cve2017-8917.nse "$TARGET" \
nmap --script=http-vuln-misfortune-cookie.nse "$TARGET" \
nmap --script=http-vuln-wnr1000-creds.nse "$TARGET" \
nmap --script=http-waf-detect.nse "$TARGET" \
nmap --script=http-waf-fingerprint.nse "$TARGET" \
nmap --script=http-webdav-scan.nse "$TARGET" \
nmap --script=http-wordpress-brute.nse "$TARGET" \
nmap --script=http-wordpress-enum.nse "$TARGET" \
nmap --script=http-wordpress-users.nse "$TARGET" \
nmap --script=http-xssed.nse "$TARGET" \
nmap --script=ip-https-discover.nse "$TARGET" \
nmap --script=membase-http-info.nse "$TARGET" \
nmap --script=riak-http-info.nse "$TARGET"
                echo "[+] Output saved to ssh-scan.txt"
                break
                ;;

            "LDAP")
                echo
                echo "[*] Running LDAP scan..."

                # Add your LDAP NSE scripts here.
                nmap --script=ldap* "$TARGET" \
                    | tee ldap-scan.txt

                echo "[+] Output saved to ldap-scan.txt"
                break
                ;;

            "SMTP")
                echo
                echo "[*] Running SMTP scan..."

                nmap --script=smtp-commands,smtp-enum-users "$TARGET" \
                    | tee smtp-scan.txt

                echo "[+] Output saved to smtp-scan.txt"
                break
                ;;

            "GIT")
                echo
                echo "[*] Running Git-related scan..."

                # Git does not have a single standard "git-scan.nse".
                # This checks common HTTP Git exposure.
                nmap --script=http-git "$TARGET" \
                    | tee git-scan.txt

                echo "[+] Output saved to git-scan.txt"
                break
                ;;

            "Exit")
                echo "[*] Exiting."
                exit 0
                ;;

            *)
                echo "[!] Invalid selection."
                ;;
        esac
    done

    echo
    read -rp "Press Enter to return to the menu..."

done
