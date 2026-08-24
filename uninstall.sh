#!/bin/bash
# ============================================================
# Script Name : uninstall-package.sh
# Description : Completely uninstall an Ubuntu Package.....
# Author      : Niranjan Bhardwaj
#Intro        : A Cybersecurty Engg
echo " Owner  : Niranjan Bhardwaj, A CyberSecurity Engg........"
# GitHub      : https://github.com/niranjanbhardwaj03
# Version     : 1.0
# Created     : 10-Aug-2026
# Updated     : 10-Aug-2026
# Platform    : Ubuntu Linux
# Use         : Run using command: bash uninstall.sh or enter package name to uninstall...
# ============================================================


echo "======================================"
echo " Ubuntu Complete Package Uninstaller"
echo "======================================"

read -rp "Enter package name to uninstall: " PACKAGE

#if [[ -z "$PACKAGE" ]]; then
#    echo "Error: Package name cannot be empty."
#    exit 1
#fi

# Check whether package exists
#if ! dpkg-query -W -f='${Status}' "$PACKAGE" 2>/dev/null | grep -q "install ok installed"; then
#    echo "Package '$PACKAGE' is not installed."
#    exit 1
#fi

echo "[1/3] Removing package and configuration files..."
sudo pkill "$PACKAGE*"
sudo apt purge -y "$PACKAGE*"
sudo apt remove -y "$PACKAGE*"
sudo rm -rf /usr/bin/"$PACKAGE*"
sudo rm -rf /usr/sbin/"$PACKAGE*"
sudo rm -rf /usr/lib/"$PACKAGE*"
sudo rm -rf /usr/libexec/"$PACKAGE*"
sudo rm -rf /usr/share/"$PACKAGE*"
sudo rm -rf /etc/"$PACKAGE*"
sudo rm -rf /var/lib/"$PACKAGE*"
sudo rm -rf /var/log/"$PACKAGE*"
sudo rm -rf /var/cache/apt/"$PACKAGE*"
sudo rm -rf /var/lib/dpkg/"$PACKAGE*"
sudo rm -rf /var/share/doc/"$PACKAGE*"
sudo rm -rf /usr/share/man/"$PACKAGE*"
sudo rm -rf /usr/share/man/man1/"$PACKAGE*"
sudo rm -rf /usr/share/man/man4/"$PACKAGE*"

echo "[2/3] Removing unused dependencies..."
sudo apt autoremove --purge -y
echo
echo "[3/3] Cleaning APT cache..."
sudo apt clean

echo
echo "======================================"
echo " Package removal completed"
echo "======================================"

if dpkg-query -W -f='${Status}' "$PACKAGE" 2>/dev/null | grep -q "install ok installed"; then
    echo "WARNING: Package '$PACKAGE' is still installed."
else
    echo "Package '$PACKAGE' has been removed."
    echo "Updating System......"
    sudo apt update -y && sudo apt upgrade -y
    echo
    echo "-------------------------> Uninstall Process is completed <------------------------------"
fi

