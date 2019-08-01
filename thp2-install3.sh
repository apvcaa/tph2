## CMSmap
#  CMSmap is a python open source CMS (Content Management System) scanner that automates the process of detecting security flaws
git clone https://github.com/Dionach/CMSmap /opt/CMSmap

## WPScan
# WordPress vulnerability scanner and brute-force tool
git clone https://github.com/wpscanteam/wpscan.git /opt/wpscan
cd /opt/wpscan && ./wpscan.rb --update

## Eyewitness
# EyeWitness is designed to take screenshots of websites, provide some server header info, and identify default credentials if possible.
git clone https://github.com/ChrisTruncer/EyeWitness.git /opt/EyeWitness

## Printer Exploits
# Contains a number of commonly found printer exploits
git clone https://github.com/MooseDojo/praedasploit /opt/praedasploit

## SQLMap
# SQL Injection tool
git clone https://github.com/sqlmapproject/sqlmap /opt/sqlmap

## Recon-ng
# A full-featured web reconnaissance framework written in Python
git clone https://bitbucket.org/LaNMaSteR53/recon-ng.git /opt/recon-ng

## Discover Scripts
# Custom bash scripts used to automate various pentesting tasks.
git clone https://github.com/leebaird/discover.git /opt/discover
cd /opt/discover && ./update.sh

## BeEF Exploitation Framework
# A cross-site scripting attack framework
cd /opt/
wget https://raw.github.com/beefproject/beef/a6a7536e/install-beef
chmod +x install-beef
./install-beef

## Responder
# A LLMNR, NBT-NS and MDNS poisoner, with built-in HTTP/SMB/MSSQL/FTP/LDAP rogue authentication server supporting NTLMv1/NTLMv2/LMv2, Extended Security NTLMSSP and Basic HTTP authentication. Responder will be used to gain NTLM challenge/response hashes
git clone https://github.com/SpiderLabs/Responder.git /opt/Responder

## The Hacker Playbook 2 - Custom Scripts
# A number of custom scripts written by myself for The Hacker Playbook 2.
git clone https://github.com/cheetz/Easy-P.git /opt/Easy-P
git clone https://github.com/cheetz/Password_Plus_One /opt/Password_Plus_One
git clone https://github.com/cheetz/PowerShell_Popup /opt/PowerShell_Popup
git clone https://github.com/cheetz/icmpshock /opt/icmpshock
git clone https://github.com/cheetz/brutescrape /opt/brutescrape
git clone https://www.github.com/cheetz/reddit_xss /opt/reddit_xss

## The Hacker Playbook 2 - Forked Versions
# Forked versions of PowerSploit and Powertools used in the book. Make sure you clone your own repositories from the original sources.
git clone https://github.com/cheetz/PowerSploit /opt/HP_PowerSploit
git clone https://github.com/cheetz/PowerTools /opt/HP_PowerTools
git clone https://github.com/cheetz/nishang /opt/nishang

## DSHashes:
# Extracts user hashes in a user-friendly format for NTDSXtract
wget http://ptscripts.googlecode.com/svn/trunk/dshashes.py -O /opt/NTDSXtract/dshashes.py

## SPARTA:
# A python GUI application which simplifies network infrastructure penetration testing by aiding the penetration tester in the scanning and enumeration phase.
git clone https://github.com/secforce/sparta.git /opt/sparta
apt-get install python-elixir
apt-get install ldap-utils rwho rsh-client x11-apps finger

## NoSQLMap
# A automated pentesting toolset for MongoDB database servers and web applications.
git clone https://github.com/tcstool/NoSQLMap.git /opt/NoSQLMap

## Spiderfoot
# Open Source Footprinting Tool
mkdir /opt/spiderfoot/ && cd /opt/spiderfoot
wget http://sourceforge.net/projects/spiderfoot/files/spiderfoot-2.3.0-src.tar.gz/download
tar xzvf download
pip install lxml
pip install netaddr
pip install M2Crypto
pip install cherrypy
pip install mako


## WCE
# Windows Credential Editor (WCE) is used to pull passwords from memory
# Download from: http://www.ampliasecurity.com/research/windows-credentials-editor/ and save to /opt/. For example:
wget www.ampliasecurity.com/research/wce_v1_4beta_universal.zip
mkdir /opt/wce && unzip wce_v1* -d /opt/wce && rm wce_v1*.zip

## Mimikatz
# Used for pulling cleartext passwords from memory, Golden Ticket, skeleton key and more
# Grab the newest release from https://github.com/gentilkiwi/mimikatz/releases/latest
cd /opt/ && wget http://blog.gentilkiwi.com/downloads/mimikatz_trunk.zip
unzip -d ./mimikatz mimikatz_trunk.zip

## SET
# Social Engineering Toolkit (SET) will be used for the social engineering campaigns
git clone https://github.com/trustedsec/social-engineer-toolkit/ /opt/set/
cd /opt/set && ./setup.py install

## PowerSploit (PowerShell)
# PowerShell scripts for post exploitation
git clone https://github.com/mattifestation/PowerSploit.git /opt/PowerSploit
cd /opt/PowerSploit && wget https://raw.githubusercontent.com/obscuresec/random/master/StartListener.py && wget https://raw.githubusercontent.com/darkoperator/powershell_scripts/master/ps_encoder.py

## Nishang (PowerShell)
# Collection of PowerShell scripts for exploitation and post exploitation
git clone https://github.com/samratashok/nishang /opt/nishang

## Veil-Framework
# A red team toolkit focused on evading detection. It currently contains Veil-Evasion for generating AV-evading payloads, Veil-Catapult for delivering them to targets, and Veil-PowerView for gaining situational awareness on Windows domains. Veil will be used to create a python based Meterpreter executable.
git clone https://github.com/Veil-Framework/Veil /opt/Veil
cd /opt/Veil/ && ./Install.sh -c

## Burp Suite Pro
# Web Penetration Testing Tool
# Download: http://portswigger.net/burp/proxy.html. I would highly recommend that you buy the professional version. It is well worth the $299 price tag.

## ZAP Proxy Pro
# OWASP ZAP: An easy-to-use integrated penetration testing tool for discovering vulnerabilities in web applications.
# Download from: https://code.google.com/p/zaproxy/wiki/Downloads?tm=2
# *Included by default in Kali Linux (owasp-zap)

## Fuzzing Lists (SecLists)
# These are scripts to use with Burp to fuzz parameters
git clone https://github.com/danielmiessler/SecLists.git /opt/SecLists

## Password Lists
## For the different password lists, see the section: Special Teams - Cracking, Exploits, and Tricks

## Net-Creds Network Parsing 
# Parse PCAP files for username/passwords
git clone https://github.com/DanMcInerney/net-creds.git /opt/net-creds

## Installing Firefox Add-ons
# Web Developer Add-on: https://addons.mozilla.org/en-US/firefox/addon/web-developer/
# Tamper Data: https://addons.mozilla.org/en-US/firefox/addon/tamper-data/
# Foxy Proxy: https://addons.mozilla.org/en-US/firefox/addon/foxyproxy-standard/
# User Agent Switcher: https://addons.mozilla.org/en-US/firefox/addon/user-agent-switcher/

## Wifite
# Attacks against WiFi networks
git clone https://github.com/derv82/wifite /opt/wifite

## WIFIPhisher
# Automated phishing attacks against WiFi networks
git clone https://github.com/sophron/wifiphisher.git /opt/wifiphisher

## Phishing (Optional):
# Phishing-Frenzy
git clone https://github.com/pentestgeek/phishing-frenzy.git /var/www/phishing-frenzy
# Custom List of Extras
git clone https://github.com/macubergeek/gitlist.git /opt/gitlist


#### My specials

