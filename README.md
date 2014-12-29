Jailsploit
==========

Exploit jail-broken iOS devices on a local LAN.  This is script is designed for a *NIX based OS.

The python 2.7 script relies on the following python modules:

os
netifaces
pexpect
logging
os.path
sys
re
socket
IPy

The tool will begin by enumerating your avaiable interfaces and displaying them for your selection.  Once you select the interface that is connected to the target network it will perform a scan for iOS devices and display their IP addresses to the terminal.

Select a target IP address from the targets provided.  The script will then validate port 22 and ask if you wish to continue.  If you select yes then it will attempt to connect to the target device allowing the following options:

Copy a specific file or directory.
Copy the entire file system.
Upload a payload to the target device.
Open a SSH connection to the target device.

USAGE:  python jailsploit.py



