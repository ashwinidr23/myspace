#!/usr/bin/env python3
# Python program to check the infra servers that are updated
# with latest kernel version and send alerts to custodians if they needs update

import subprocess
import json
import os
import re
import csv
import datetime


# Opening JSON file
j = open('/usr/local/etc/kernel-config.json',)
#j = open('test.json',)
kerconfig = json.load(j)

# returns JSON object as a dictionary
userjson = subprocess.getoutput("hammer --output json user list")
#userjson = open('user2.json',)
userlist = json.loads(userjson)
#userlist = json.load(userjson)
acceptable_versions = []


### check the config file for acceptable kernel  version and save it in list"
for aver_item in kerconfig:
 for aver in aver_item:
  if (aver_item[aver].get("Current") == "True"):
   acceptable_list = aver_item[aver].get("OS") + " - " + aver_item[aver].get("Version")
   acceptable_versions.append(acceptable_list)


# Iterating through the json list
#kernels = subprocess.check_output("hammer --no-headers fact list --search 'name = kernelrelease'", shell=True)
consolidatedvmlist = []
unsupportedvmlist = []
for user in userlist:
       if user["Name"] == " ":
        print(user["Id"])
        print("The Id does not have valid email ID, Please assign a valid owner to the hosts assigned to the ID")
        #mail_body = "Hi Team,\n\n The ID %s does not have valid email ID, Please assign a valid owner to the hosts assigned to the ID" %user["Id"]
        #mail_command = f"echo -e '{mail_body}' | mail -s 'security patching - update Owner details' -c ashwini.dr@shell.com ashwini.dr@shell.com"
        #subprocess.getoutput(mail_command)
        continue

       ## ignore admin user as it has the compue nodes
       if user["Id"] == 4:
        continue
       else :
        print(user["Id"], user["Name"], user["Email"])
        id=user["Id"]
        list = subprocess.getoutput("hammer --no-headers host list --search 'owner_id=%s' | cut -d '|' -f 2 | tr -d ' ' "%(id))
#        kernel_list = kernels.decode().splitlines()

        kernelver = " "
        #print(type(kernel_list))
        vmlist = list.split("\n")
        vmpatch = []
        if vmlist == ['']:
         continue
        else :
         print(vmlist)
         for vm in vmlist:
                  vmname =  vm.split('.')[0]
                  region = subprocess.getoutput('nodeattr -n "location=Houston||location=Bangalore||location=PetalingJaya||location=Amsterdam" | grep %s' %(vmname))
                  if vmname in region:
                   #print(vm)
                   facts = subprocess.getoutput("hammer host facts --search 'host=%s'" %(vm))
                   kernelver = subprocess.getoutput("hammer host facts --search 'host=%s'| grep -w 'facter_kernelrelease' | cut -d '|' -f 2 | tr -d ' '" %(vm))
                   #kernelver = subprocess.getoutput("hammer host facts --search 'host=%s'| grep -w 'uname::release' | cut -d '|' -f 2 | tr -d ' '" %(vm))
                   #print(vm +" is running on kernel version " + kernelver)
                   for kver in kerconfig:
                        #print(" vm " + vm)
                        for kitem in kver:
                         ### skip the host if it is in the skip list in confog.json ###
                         exemptions = kerconfig[0]['host_exemptions']
                         if vm in exemptions:
                          print ("skipping the host " + vm + " as it is part of host_exemption list")
                          break
                         ### if the kernel version of host is none, send email
                         if (kernelver == "" ):
                          print ("host " + vm + " has invalid kernel version")
                          #mail_body = "Hi Team,\n\n Host %s does not have a valid kernel version , please update the host in satellite" %(vm)
                          #mail_command = f"echo -e '{mail_body}' | mail -s 'Security patching - invalid kernel version' -c ashwini.dr@shell.com ashwini.dr@shell.com"
                          #subprocess.getoutput(mail_command)
                          break
                          #print("kitem " + kitem + " vm " + vm + " kernel version " + kernelver )

                         ## check the kernel version of vm against the config.json and see if it is current. send email if it is not current
                         if (kver[kitem].get("Version") == kernelver):
                             #print("kernerl version matched")
                             if (kver[kitem].get("Current") == "True"):
                                print(vm +" is running on latest kernel version " +kernelver + " no update needed")
                                #osver = kver[kitem].get("OS")
                                break
                             else :
                                print(vm +" is running on " + kernelver + " needs update, sending email to user")
                                uservmlist = vm + " - " + kver[kitem].get("OS") + " - existing Kernel: " + kernelver + "\t"
                                #consolidatedlist = [user["Name"] + "," + vm + "," + kernelver]
                                if (kver[kitem].get("Supported") == "False"):
                                        unsupportedlist =  [user["Name"],vm,kernelver,kver[kitem].get("Comment")]
                                        unsupportedvmlist.append(unsupportedlist)
                                consolidatedlist = [user["Name"],vm,kernelver]
                                vmpatch.append(uservmlist)
                                consolidatedvmlist.append(consolidatedlist)
                                break
                                #continue
                         else :
                             #print ("version not matched")
                             continue
                        else :
                            print( "kernel version " + kernelver + " is not found in the json file, please update the json file")
                            mail_body = "Hi Team,\n\n Kernel Version %s is not found in the config.json file, please update the json file.\nFor more details please refer: https://htwiki.shell.com/wiki/index.php?title=Security_patching_Alerting" %(kernelver)
                            #mailcc = "GXITSOSOMPTHPCOS@shell.com"
                            #mailto = "Pramod.Raju@shell.com,Nishit.J.Patel@shell.com,John.Thiesfeld@shell.com,ashwini.dr@shell.com,grace.stellara@shell.com"
                            mailto = "ashwini.dr@shell.com"
                            mailcc = "ashwini.dr@shell.com,ashwini.dr@shell.com"
                            mail_command = f"echo -e '{mail_body}' | mail -s 'Action Required: HPC quarterly Security Patching - update config file' -c '{mailcc}' '{mailto}'"
                            subprocess.getoutput(mail_command)
       print("Following nodes need update")
       print(vmpatch)
       if len(vmpatch) == 0:
          print("all vm's are updated")
          continue
       else :
          mail_subject = "ACTION REQUIRED: Apply HPC quarterly Security Patching"
          #mail_cc = "Ricardo.Gonzalez@shell.com,noella.soares@shell.com"
          #mail_to = user["Email"]
          mail_to = "ashwini.dr@shell.com"
          mail_cc = "ashwini.dr@shell.com"
          mail_body = "Hi %s,\n\nYou are receiving this email because you are listed as the custodian of HPC managed Linux systems which are not running the latest security patched kernel.This indicates that the systems are in need of security patching. Can you please either upgrade the system or reach out to operations - GXITSOSOMPTHPCOpsSupport@shell.com to schedule a time for upgrade?\n\nThe servers must be updated with the latest security patches quarterly so that the HPC Landscape can be compliant with IRM guidelines and keep its license to operate. This activity will require reboot. Please save your work before security patching.\n\nGeneral steps for patching systems:\nplease refer: https://htwiki.shell.com/wiki/index.php?title=Security_patching_of_Infra_servers#Steps_for_Security_patching. \n\nBelow is the details of server(s) and kernel versions running that requires update.\n%s\n\nCurrently supported list of kernels:\n%s \n\nIf you encounter any problems or need assistance, please send an email to GXITSOSOMPTHPCOS@shell.com\n\n* if you are not the custodian of some or all of the above mentioned systems, please send an email to  GXITSOSOMPTHPCOS@shell.com to get this rectified*\n\nLink to infra servers page - https://htwiki.shell.com/wiki/index.php?title=Infrastructure_Servers\n\nBest Regards," %(user["Name"], "\n" .join(vmpatch), "\n" .join(acceptable_versions))
          mail_command = f"echo -e '{mail_body}' | mail -s '{mail_subject}' -c '{mail_cc}' '{mail_to}'"
          subprocess.getoutput(mail_command)

#send consolidate list of all users
print("This is consolidated vm list that require pathching")
print(consolidatedvmlist)
if len(consolidatedvmlist) != 0:
    fields = ['Owner', 'Hostname', 'Kernel_version']
    cur_date = datetime.datetime.now()
    formatted_date = cur_date.strftime("%Y%m%d")
    filename = "consolidated-patching-list_" + formatted_date + ".csv"
    dir_path = "/var/log/infra-security-patching-logs"
    if not os.path.exists(dir_path):
        os.makedirs(dir_path)
        print(f"Directory '{dir_path}' created successfully.")
    consolidated_file_path = os.path.join(dir_path, filename)
    with open(consolidated_file_path, "w") as file:
     csv_writer = csv.writer(file)
     csv_writer.writerow(fields)
     csv_writer.writerows(consolidatedvmlist)
    #mail_to_list = "christopher.cupples@shell.com,noella.soares@shell.com,Ricardo.Gonzalez@shell.com"
    mail_to_list = "ashwini.dr@shell.com"
    mail_cc_list = "ashwini.dr@shell.com"
    #mail_cc_list = "Ricardo.Gonzalez@shell.com,Nishit.J.Patel@shell.com,John.Thiesfeld@shell.com,ashwini.dr@shell.com,Pramod.Raju@shell.com,S.Patchamatla@shell.com,grace.stellara@shell.com"
    mail_body2 = "Hi All, \n PFA, The Consolidated list of infra servers that require Security patching.\n"
    mail_command2 = f"echo -e '{mail_body2}' | mail -a {consolidated_file_path} -s 'Infra Servers Security patching - consolidated list' -c {mail_to_list} {mail_cc_list}"
    subprocess.getoutput(mail_command2)
else:
    print("There are no servers that are behind security patching")

#send the non-compliant vm list to IRM focal for review
print("This is the list of VMs that are more than 2 patches behind and needs to be updated on priority")
print(unsupportedvmlist)
if len(unsupportedvmlist) != 0:
    fields = ['Owner', 'Hostname', 'Kernel_version', 'Comment']
    cur_date = datetime.datetime.now()
    formatted_date = cur_date.strftime("%Y%m%d")
    filename = "unsupported-vmpatching-list_" + formatted_date + ".csv"
    dir_path = "/var/log/infra-security-patching-logs"
    if not os.path.exists(dir_path):
        os.makedirs(dir_path)
        print(f"Directory '{dir_path}' created successfully.")
    unsupported_file_path = os.path.join(dir_path, filename)
    with open(unsupported_file_path, "w") as file:
     csv_writer = csv.writer(file)
     csv_writer.writerow(fields)
     csv_writer.writerows(unsupportedvmlist)
    #mail_to_list3 = "noella.soares@shell.com"
    mail_to_list3 = "ashwini.dr@shell.com"
    mail_body3 = "Hi All, \n PFA, The list of infra servers that are more than 2 patches behind and requires Security patching on priority.\n"
    mail_command3 = f"echo -e '{mail_body3}' | mail -a {unsupported_file_path} -s 'IMP - Infra Servers running outdated kernel versions - consolidated list' {mail_to_list3}"
    subprocess.getoutput(mail_command3)
else:
    print("There are no servers that are more than 2 patches behind")

