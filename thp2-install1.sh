passwd
apt-get update
apt-get dist-upgrade
# Setup Metasploit database
service postgresql start
# Make postgresql database start on boot
update-rc.d postgresql enable
# Start and stop the Metasploit service (this will setup the database.yml file for you)
service metasploit start
service metasploit stop
# Install gedit
apt-get install gedit
# Change the hostname - Many network admins look for systems named Kali in logs like DHCP. It is best to follow the naming standard used by the company you are testing
gedit /etc/hostname
## Change the hostname (replace kali) and save
gedit /etc/hosts
## Change the hostname (replace kali) and save
reboot
## I list this as optional since logs get pretty big, but you have the ability to log every command and result from Metasploit’s Command Line Interface (CLI). This becomes very useful for bulk attack/queries or if your client requires these logs. *If this is a fresh image, type msfconsole first and exit before configuring logging to create the .msf4 folder.
# From a command prompt, type:
echo “spool /root/msf_console.log” > /root/.msf4/msfconsole.rc
# Logs will be stored at /root/msf_console.log