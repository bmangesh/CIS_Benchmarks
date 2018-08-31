#!/bin/bash
Author: Mangesh Bharsakle
###############################
# CIS Benchmark FOR Ubuntu 18.04
###############################
WIDTH=79
CIS_LEVEL=1
INCLUDE_UNSCORED=0
WIDTH=79
if [ $CIS_LEVEL -gt 1 ];then
  RESULT_FIELD=10
else
  RESULT_FIELD=6
fi
MSG_FIELD=$(($WIDTH - $RESULT_FIELD))
RED=$(tput setaf 1)
GREEN=$(tput setaf 2)
YELLOW=$(tput setaf 3)
NC=$(tput sgr0)
PASSED_CHECKS=0
FAILED_CHECKS=0

function header() {
    local HEADING=$1
    local TEXT=$((${#HEADING}+2))
    local LBAR=5
    local RBAR=$(($WIDTH - $TEXT - $LBAR))
    echo ""
    for (( x=0; x < $LBAR; x++));do
        printf %s '#'
    done
    echo -n " $HEADING "
    for (( x=0; x < $RBAR; x++));do
        printf %s '#'
    done
    echo ""
}

function msg() {
  printf "%-${MSG_FIELD}s" " - ${1}"
}

function success_result() {
    PASSED_CHECKS=$((PASSED_CHECKS+1))
    local RESULT="$GREEN${1:-PASSED}$NC"
    printf "%-${RESULT_FIELD}s\n" $RESULT
}

function failed_result() {
    FAILED_CHECKS=$((FAILED_CHECKS+1))
    local RESULT="$RED${1:-FAILED}$NC"
    printf "%-${RESULT_FIELD}s\n" $RESULT
}

function warning_result() {
    local RESULT="$YELLOW${1:-NOT CHECKED}$NC"
    printf "%-${RESULT_FIELD}s\n" $RESULT
}

function check_retval_eq_0() {
  RETVAL=$1
  if [ $RETVAL -eq 0 ]; then
    success_result
  else
    failed_result
  fi
}

function check_retval_ne_0() {
  RETVAL=$1
  if [ $RETVAL -ne 0 ]; then
    success_result
  else
    failed_result
  fi
}

##1.1.2 Ensure separate partition exists for /tmp

  header "6.1.10 Ensure no world writable files exist"
  msg 'mount | grep /tmp'
  mount | grep /tmp > /dev/null
  check_retval_eq_0 $?


##1.1.3 Ensure nodev option set on /tmp partition
  header "1.1.3 Ensure nodev option set on /tmp partition"
  msg 'mount | grep /tmp | grep nodev'
  mount | grep /tmp | grep  nodev > /dev/null
  check_retval_eq_0 $?

##1.1.4 Ensure nosuid option set on /tmp partition
  header "1.1.4 Ensure nosuid option set on /tmp partition"
  msg 'mount | grep /tmp | grep nosuid'
  mount | grep /tmp | grep  nosuid > /dev/null
  check_retval_eq_0 $?

##1.1.5 Ensure separate partition exists for /var
  header "1.1.5 Ensure separate partition exists for /var"
  msg 'mount | grep /var'
  mount | grep /var > /dev/null
  check_retval_eq_0 $?

##1.1.6 Ensure separate partition exists for /var/tmp
  header "1.1.6 Ensure separate partition exists for /var/tmp"
  msg 'mount | grep /var/tmp'
  mount | grep /var/tmp > /dev/null
  check_retval_eq_0 $?

##1.1.7 Ensure nodev option set on /var/tmp partition
  header "1.1.7 Ensure nodev option set on /var/tmp partition"
  msg 'mount | grep /var/tmp | grep nodev'
  mount | grep /var/tmp | grep nodev > /dev/null
  check_retval_eq_0 $?

##1.1.8 Ensure nosuid option set on /var/tmp partition
  header "#1.1.8 Ensure nosuid option set on /var/tmp partition"
  msg 'mount | grep /var/tmp | grep nosuid'
  mount | grep /var/tmp | grep nosuid > /dev/null
  check_retval_eq_0 $?

##1.1.9 Ensure noexec option set on /var/tmp partition
  header "1.1.9 Ensure noexec option set on /var/tmp partition"
  msg 'mount | grep /var/tmp | grep noexec'
  mount | grep /var/tmp | grep noexec > /dev/null
  check_retval_eq_0 $?
##1.1.10 Ensure separate partition exists for /var/log
  header "1.1.10 Ensure separate partition exists for /var/log"
  msg 'mount | grep /var/log'
  mount | grep /var/log > /dev/null
  check_retval_eq_0 $?

##1.1.11 Ensure separate partition exists for /var/log/audit
  header "#1.1.11 Ensure separate partition exists for /var/log/audit"
  msg 'mount | grep /var/log/audit'
  mount | grep /var/log/audit > /dev/null
  check_retval_eq_0 $?

##1.1.12 Ensure separate partition exists for /home
  header "1.1.12 Ensure separate partition exists for /home"
  msg 'mount | grep /home'
  mount | grep /home > /dev/null
  check_retval_eq_0 $?

##1.1.13 Ensure nodev option set on /home partition
  header "#1.1.13 Ensure nodev option set on /home partition"
  msg 'mount | grep /home | grep nodev'
  mount | grep /home | grep nodev > /dev/null
  check_retval_eq_0 $?

##1.1.14 Ensure nodev option set on /dev/shm partition
  header "1.1.14 Ensure nodev option set on /dev/shm partition"
  msg 'mount | grep /dev/shm'
  mount | grep /dev/shm > /dev/null
  check_retval_eq_0 $?

##1.1.15 Ensure nosuid option set on /dev/shm partition
  header "1.1.15 Ensure nosuid option set on /dev/shm partition"
  msg 'mount | grep /dev/shm'
  mount | grep /dev/shm | grep nosuid > /dev/null
  check_retval_eq_0 $?

##1.1.16 Ensure noexec option set on /dev/shm partition
  header "1.1.16 Ensure noexec option set on /dev/shm partition"
  msg 'mount | grep /dev/shm'
  mount | grep /dev/shm | grep noexec > /dev/null
  check_retval_eq_0 $?

##1.1.20 Ensure sticky bit is set on all world-writable directories
  header "1.1.20 Ensure sticky bit is set on all world-writable directories"
  msg 'df --local -P | awk ...'
  df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type d \( -perm -0002 -a ! -perm -1000 \) 2>/dev/null > /dev/null
  check_retval_eq_0 $?

##1.1.21 Disable Automounting
 header "1.1.21 Disable Automounting"
 msg 'systemctl is-enabled autofs'
 systemctl is-enabled autofs 2> /dev/null | grep disabled > /dev/null
 check_retval_eq_0 $?

##1.3.1 Ensure AIDE is installed
  header "1.3.1 Ensure AIDE is installed"
  msg 'dpkg -s aide'
  dpkg -s aide > /dev/null 2> /dev/null
  check_retval_eq_0 $?

##1.3.2 Ensure filesystem integrity is regularly checked
  header "1.3.2 Ensure filesystem integrity is regularly checked"
  msg 'grep -r aide /etc/cron.* /etc/crontab'
  grep -r aide /etc/cron.* /etc/crontab > /dev/null
  check_retval_eq_0 $?

##1.4.1 Ensure permissions on bootloader config are configured
  header "1.4.1 Ensure permissions on bootloader config are configured"
  msg 'stat /boot/grub/grub.cfg'
  if [[ $(stat /boot/grub/grub.cfg) =~ Access:.*(0600/-rw-------).*Uid:.*(.*0/.*root).*Gid:.*(.*0/.*root) ]];then
        success_result
    else
        failed_result
    fi
##1.4.2 Ensure bootloader password is set
  header "1.4.2 Ensure bootloader password is set"
  msg 'grep "^set superusers" AND "^password" /boot/grub/grub.cfg'
  var=`grep "^set superusers" /boot/grub/grub.cfg  > /dev/null ; echo $?`
  var2=`grep "^password" /boot/grub/grub.cfg > /dev/null; echo $?`


	if [  "$var" -eq 0 -a "$var2" = 0  ]; then
     		success_result
	else
   		failed_result

	fi
##1.4.3 Ensure authentication required for single user mode
  header "1.4.3 Ensure authentication required for single user mode"
  msg 'grep ^root:[*\!]: /etc/shadow'
  grep ^root:[*\!]: /etc/shadow > /dev/null
  check_retval_ne_0 $?

##1.5.1 Ensure core dumps are restricted
  header "1.5.1 Ensure core dumps are restricted"
  msg 'grep "hard core" /etc/security/limits.conf /etc/security/limits.d/*'
  var3=`grep "hard core" /etc/security/limits.conf /etc/security/limits.d/* 2> /dev/null > /dev/null ; echo $?`
  var4=`grep "fs\.suid_dumpable" /etc/sysctl.conf /etc/sysctl.d/* 2> /dev/null > /dev/null ; echo $?`
	if [  "$var3" -eq 0 -a "$var4" = 0  ]; then
                success_result
        else
                failed_result

        fi
##1.5.3 Ensure address space layout randomization (ASLR) is enabled
  header "1.5.3 Ensure address space layout randomization (ASLR) is enabled"
  msg 'grep "kernel\.randomize_va_space" /etc/sysctl.conf /etc/sysctl.d/*'
  grep "kernel\.randomize_va_space" /etc/sysctl.conf /etc/sysctl.d/* 2> /dev/null > /dev/null
  check_retval_eq_0 $?

##1.5.4 Ensure prelink is disabled
  header "1.5.4 Ensure prelink is disabled"
  msg 'dpkg -s prelink'
  dpkg -s prelink 2> /dev/null > /dev/null
  check_retval_ne_0 $?

##1.6.1.1 Ensure SELinux is not disabled in bootloader configuration
  header "1.6.1.1 Ensure SELinux is not disabled in bootloader configuration"
  msg 'grep "^\s*linux" /boot/grub/grub.cfg'
  grep "^\s*linux"  /boot/grub/grub.cfg 2> /dev/null  | grep -E 'selinux=0|enforcing=0' > /dev/null
  check_retval_ne_0 $?

##1.6.1.2 Ensure the SELinux state is enforcing
  header "1.6.1.2 Ensure the SELinux state is enforcing"
  msg 'grep SELINUX=enforcing /etc/selinux/config'
  grep SELINUX=enforcing /etc/selinux/config 2> /dev/null > /dev/null
  check_retval_eq_0 $?

##1.6.1.3 Ensure SELinux policy is configured
  header "1.6.1.3 Ensure SELinux policy is configured"
  msg 'grep SELINUXTYPE= /etc/selinux/config'
  grep SELINUXTYPE= /etc/selinux/config 2> /dev/null | grep -E "default|ubuntu|mls" > /dev/null
  check_retval_eq_0 $?

##1.6.1.4 Ensure no unconfined daemons exist
  header "1.6.1.4 Ensure no unconfined daemons exist"
  msg ' ps -eZ | egrep "initrc" .......'
  var5=`ps -eZ | egrep "initrc" | egrep -vw "tr|ps|egrep|bash|awk" | tr ':' ' ' | awk '{ print $NF }' > /dev/null`
        if [  -z "$var5"  ]; then
                success_result
        else
                failed_result

        fi
 
##1.6.2.1 Ensure AppArmor is not disabled in bootloader configuration
  header "1.6.2.1 Ensure AppArmor is not disabled in bootloader configuration"
  msg 'grep "^\s*linux" /boot/grub/grub.cfg'
  grep "^\s*linux"  /boot/grub/grub.cfg 2> /dev/null  | grep  'apparmor=0' > /dev/null
  check_retval_ne_0 $?



##1.6.2.2 Ensure all AppArmor Profiles are enforcing
  header "1.6.2.2 Ensure all AppArmor Profiles are enforcing"
  msg 'apparmor_status'
  var7=`apparmor_status 2> /dev/null | grep "complain mode" | head -1 | grep ^0 > /dev/null; echo $?`

  var8=`apparmor_status 2> /dev/null  | grep "processes are unconfined" | grep ^0 > /dev/null ; echo $?`

  var10=`apparmor_status 2> /dev/null | grep "profiles are loaded." | grep ^0  > /dev/null; echo $?`

        if [  "$var7" -eq 0 -a "$var8" = 0  ]; then
                success_result
        else
                failed_result

        fi

##1.6.3 Ensure SELinux or AppArmor are installed
  header "1.6.3 Ensure SELinux or AppArmor are installed"
  msg 'dpkg -s selinux apparmor'
  dpkg -s selinux apparmor 2> /dev/null > /dev/null
  check_retval_eq_0 $?


##1.7.1.1 Ensure message of the day is configured properly
  header "1.7.1.1 Ensure message of the day is configured properly"
  msg 'cat /etc/motd and egrep (\\v|\\r|\\m|\\s)" /etc/motd'
  egrep '(\\v|\\r|\\m|\\s)' /etc/motd 2> /dev/null > /dev/null
  check_retval_ne_0 $?

##1.7.1.2 Ensure local login warning banner is configured properly
  header "1.7.1.2 Ensure local login warning banner is configured properly"
  msg 'egrep "(\\v|\\r|\\m|\\s)" /etc/issue'
  egrep '(\\v|\\r|\\m|\\s)' /etc/issue 2> /dev/null > /dev/null
  check_retval_ne_0 $?

##1.7.1.3 Ensure remote login warning banner is configured properly
  header "1.7.1.3 Ensure remote login warning banner is configured properly"
  msg 'egrep "(\\v|\\r|\\m|\\s)" /etc/issue.net'
  egrep '(\\v|\\r|\\m|\\s)' /etc/issue.net 2> /dev/null > /dev/null
  check_retval_ne_0 $?

##1.7.1.4 Ensure permissions on /etc/motd are configured
  header "1.7.1.4 Ensure permissions on /etc/motd are configured"
  msg 'stat /etc/motd'
      if [[ $(stat /etc/motd 2> /dev/null) =~ Access:.*(0644/-rw-r--r--).*Uid:.*(.*0/.*root).*Gid:.*(.*0/.*root) ]];then
          success_result
      else
          failed_result
      fi


##1.7.1.5 Ensure permissions on /etc/issue are configured
  header "1.7.1.5 Ensure permissions on /etc/issue are configured"
  msg 'stat /etc/issue'
     if [[ $(stat /etc/issue 2> /dev/null) =~ Access:.*(0644/-rw-r--r--).*Uid:.*(.*0/.*root).*Gid:.*(.*0/.*root) ]];then
          success_result
      else
          failed_result
      fi

##1.7.1.6 Ensure permissions on /etc/issue.net are configured
  header "1.7.1.6 Ensure permissions on /etc/issue.net are configured"
  msg 'stat /etc/issue.net'
     if [[ $(stat /etc/issue.net 2> /dev/null) =~ Access:.*(0644/-rw-r--r--).*Uid:.*(.*0/.*root).*Gid:.*(.*0/.*root) ]];then
          success_result
      else
          failed_result
      fi


##1.7.2 Ensure GDM login banner is configured
  header "1.7.2 Ensure GDM login banner is configured"
  msg '/etc/gdm3/greeter.dconf-defaults'
  echo " "
  dpkg -s gdm3 2>  /dev/null > /dev/null
    if [ $? -ne 0 ];then
  msg 'gdm3 not even installed'
        success_result
    else
        msg ' Checking GDM conf'
        [[ $(grep "login-screen" /etc/gdm3/greeter.dconf-defaults) ]] && \
        [[ $(grep "banner-message-enable=true" /etc/gdm3/greeter.dconf-defaults) ]] && \
        [[ $(grep "banner-message-text=" /etc/gdm3/greeter.dconf-defaults) ]] && \
        success_result || \
        failed_result
    fi

##2.1.1 Ensure chargen services are not enabled
  header "2.1.1 Ensure chargen services are not enabled"
  msg 'grep -R "^chargen" /etc/inetd.*'
  grep -R "^chargen" /etc/inetd.* 2> /dev/null > /dev/null
  check_retval_ne_0 $?

##2.1.2 Ensure daytime services are not enabled
  header "2.1.2 Ensure daytime services are not enabled"
  msg 'grep -R "^daytime" /etc/inetd.*'
  grep -R "^daytime" /etc/inetd.* 2> /dev/null > /dev/null
  check_retval_ne_0 $?

##2.1.3 Ensure discard services are not enabled
  header "2.1.3 Ensure discard services are not enabled"
  msg 'grep -R "^discard" /etc/inetd.*'
  grep -R "^discard" /etc/inetd.* 2> /dev/null > /dev/null
  check_retval_ne_0 $?

##2.1.4 Ensure echo services are not enabled
  header "2.1.4 Ensure echo services are not enabled"
  msg 'grep -R "^echo" /etc/inetd.*'
  grep -R "^echo" /etc/inetd.* 2> /dev/null > /dev/null
  check_retval_ne_0 $?

##2.1.5 Ensure time services are not enabled
  header "2.1.5 Ensure time services are not enabled"
  msg 'grep -R "^time" /etc/inetd.*'
  grep -R "^time" /etc/inetd.* 2> /dev/null > /dev/null
  check_retval_ne_0 $?

##2.1.6 Ensure rsh server is not enabled
  header "2.1.6 Ensure rsh server is not enabled"
  msg 'grep -RE "^shell" and "^login and ^exec /etc/inetd.*'
  grep -RE "^shell|^login|^exec" 2> /dev/null > /dev/null
  check_retval_ne_0 $?

##2.1.7 Ensure talk server is not enabled
  header "2.1.7 Ensure talk server is not enabled"
  msg 'grep -R "^talk" and -R "^ntalk" /etc/inetd.*'
  grep -RE "^talk|^ntalk" /etc/inetd.* 2> /dev/null > /dev/null
  check_retval_ne_0 $?

##2.1.8 Ensure telnet server is not enabled
  header "2.1.8 Ensure telnet server is not enabled"
  msg 'grep -R "^telnet" /etc/inetd.*'
  grep -R "^telnet" /etc/inetd.* 2> /dev/null > /dev/null
  check_retval_ne_0 $?

##2.1.9 Ensure tftp server is not enabled
  header "2.1.9 Ensure tftp server is not enabled"
  msg 'grep -R "^tftp" /etc/inetd.*'
  grep -R "^tftp" /etc/inetd.* 2> /dev/null > /dev/null
  check_retval_ne_0 $?

##2.1.10 Ensure xinetd is not enabled
  header "2.1.10 Ensure xinetd is not enabled"
  msg 'systemctl is-enabled xinetd'
  systemctl is-enabled xinetd 2> /dev/null | grep disabled > /dev/null
  check_retval_ne_0 $?

##2.1.11 Ensure openbsd-inetd is not installed
  header "2.1.11 Ensure openbsd-inetd is not installed"
  msg 'dpkg -s openbsd-inetd'
  dpkg -s openbsd-inetd 2> /dev/null > /dev/null
  check_retval_ne_0 $?

####2.2.1.2 Ensure ntp is configured
  header "2.2.1.2 Ensure ntp is configured"
  dpkg -s ntp 2>  /dev/null > /dev/null
    if [ $? -ne 0 ];then
  	msg 'ntp not even installed'
        success_result
    else

          header "2.2.1.2 Ensure ntp is configured"
          msg 'grep "^restrict" /etc/ntp.conf'
	  echo " "
          var15=`grep "^restrict" /etc/ntp.conf 2>&1 > /dev/null | echo $?`
          #check_retval_eq_0 $?
          msg "grep "^server" /etc/ntp.conf"
	  echo " "
          var16=`egrep "^(server|pool)" /etc/ntp.conf 2>&1 > /dev/null | echo $?`
          #check_retval_eq_0 $?
          msg 'grep "RUNASUSER=ntp" /etc/init.d/ntp'
          var17=`grep "RUNASUSER=ntp" /etc/init.d/ntp 2>&1 > /dev/null | echo $?`
          #check_retval_eq_0 $?
	  if [  $var15 -eq 0 -a $var16 -eq 0  ]; then
		  success_result
          else
		  failed_result
	  fi
   fi


##2.2.1.3 Ensure chrony is configured
  header "2.2.1.3 Ensure chrony is configured"
  dpkg -s chrony 2> /dev/null > /dev/null
  if [ $? -ne 0 ];then
        msg 'chrony not even installed'
        success_result
    else
	    
	msg '^(server|pool)" /etc/chrony/chrony.conf'    
	grep "^(server|pool)" /etc/chrony/chrony.conf 2> /dev/null > /dev/null
        check_retval_eq_0 $?


  fi	    
##2.2.2 Ensure X Window System is not installed
  header "2.2.2 Ensure X Window System is not installed"
  msg 'dpkg -l xserver-xorg*'
  dpkg -l xserver-xorg* 2> /dev/null  > /dev/null
  check_retval_ne_0 $?

##2.2.3 Ensure Avahi Server is not enabled
  header "2.2.3 Ensure Avahi Server is not enabled"
  msg 'systemctl is-enabled avahi-daemon'
  systemctl is-enabled avahi-daemon 2> /dev/null | grep disabled > /dev/null
  check_retval_ne_0 $?

##2.2.4 Ensure CUPS is not enabled
  header "2.2.4 Ensure CUPS is not enabled"
  msg 'systemctl is-enabled cups'
  systemctl is-enabled cups 2> /dev/null | grep disabled > /dev/null
  check_retval_ne_0 $?

##2.2.5 Ensure DHCP Server is not enabled
  header "2.2.5 Ensure DHCP Server is not enabled"
  msg 'systemctl is-enabled isc-dhcp-server'
  systemctl is-enabled isc-dhcp-server 2> /dev/null | grep disabled > /dev/null
  check_retval_ne_0 $?

##2.2.6 Ensure LDAP server is not enabled
  header "2.2.6 Ensure LDAP server is not enabled"
  msg 'systemctl is-enabled slapd'
  systemctl is-enabled slapd 2> /dev/null | grep disabled > /dev/null
  check_retval_ne_0 $?

##2.2.7 Ensure NFS and RPC are not enabled
  header "2.2.7 Ensure NFS and RPC are not enabled"
  msg 'systemctl is-enabled nfs-server'
  systemctl is-enabled nfs-server 2> /dev/null | grep disabled > /dev/null
  check_retval_ne_0 $?

##2.2.8 Ensure DNS Server is not enabled
  header "2.2.8 Ensure DNS Server is not enabled"
  msg 'systemctl is-enabled bind9'
  systemctl is-enabled bind9 2> /dev/null | grep disabled > /dev/null
  check_retval_ne_0 $?

##2.2.9 Ensure FTP Server is not enabled
  header "2.2.9 Ensure FTP Server is not enabled"
  msg 'systemctl is-enabled vsftpd'
  systemctl is-enabled vsftpd 2> /dev/null | grep disabled > /dev/null
  check_retval_ne_0 $?

##2.2.10 Ensure HTTP server is not enabled
  header "2.2.10 Ensure HTTP server is not enabled"
  msg 'systemctl is-enabled apache2'
  systemctl is-enabled apache2 2> /dev/null | grep disabled > /dev/null
  check_retval_ne_0 $?

##2.2.11 Ensure IMAP and POP3 server is not enabled
  header "2.2.11 Ensure IMAP and POP3 server is not enabled"
  msg 'systemctl is-enabled dovecot'
  systemctl is-enabled dovecot 2> /dev/null | grep disabled > /dev/null
  check_retval_ne_0 $?

##2.2.12 Ensure Samba is not enabled
  header "2.2.12 Ensure Samba is not enabled"
  msg 'systemctl is-enabled smbd'
  systemctl is-enabled smbd 2> /dev/null | grep disabled > /dev/null
  check_retval_ne_0 $?

##2.2.13 Ensure HTTP Proxy Server is not enabled
  header "2.2.13 Ensure HTTP Proxy Server is not enabled"
  msg 'systemctl is-enabled squid'
  systemctl is-enabled squid 2> /dev/null | grep disabled > /dev/null
  check_retval_ne_0 $?

##2.2.14 Ensure SNMP Server is not enabled
  header "2.2.14 Ensure SNMP Server is not enabled"
  msg 'systemctl is-enabled snmpd'
  systemctl is-enabled snmpd 2> /dev/null | grep disabled > /dev/null
  check_retval_ne_0 $?

##2.2.15 Ensure mail transfer agent is configured for local-only mode
  header "2.2.15 Ensure mail transfer agent is configured for local-only mode"
  msg 'netstat -an | grep LIST | grep ":25[[:space:]]"'
  netstat -an | grep LISTEN | grep ":25[[:space:]]"  | grep -vE "127.0.0.1|::1" 2>&1 > /dev/null
  check_retval_ne_0 $?

##2.2.16 Ensure rsync service is not enabled
  header "2.2.16 Ensure rsync service is not enabled"
  msg 'systemctl is-enabled rsync'
  systemctl is-enabled rsync 2> /dev/null | grep disabled > /dev/null
  check_retval_ne_0 $?

##2.2.17 Ensure NIS Server is not enabled
  header "2.2.17 Ensure NIS Server is not enabled"
  msg 'systemctl is-enabled nis'
  systemctl is-enabled nis 2> /dev/null | grep disabled > /dev/null
  check_retval_ne_0 $?

##2.3.1 Ensure NIS Client is not installed
  header "2.3.1 Ensure NIS Client is not installed"
  msg 'dpkg -s nis'
  dpkg -s nis 2> /dev/null > /dev/null
  check_retval_ne_0 $?

##2.3.2 Ensure rsh client is not installed
  header "2.3.2 Ensure rsh client is not installed"
  msg 'dpkg -s rsh-client rsh-redone-client'
  dpkg -s rsh-client rsh-redone-client 2> /dev/null > /dev/null
  check_retval_ne_0 $?

##2.3.3 Ensure talk client is not installed
  header "2.3.3 Ensure talk client is not installed"
  msg 'dpkg -s talk'
  dpkg -s talk 2> /dev/null > /dev/null
  check_retval_ne_0 $?

##2.3.4 Ensure telnet client is not installed
  header "2.3.4 Ensure telnet client is not installed"
  msg 'dpkg -s telnet'
  dpkg -s telnet 2> /dev/null > /dev/null
  check_retval_ne_0 $?

##2.3.5 Ensure LDAP client is not installed
  header "2.3.5 Ensure LDAP client is not installed"
  msg 'dpkg -s ldap-utils'
  dpkg -s ldap-utils 2> /dev/null > /dev/null
  check_retval_ne_0 $?

##3.1.1 Ensure IP forwarding is disabled
  header "3.1.1 Ensure IP forwarding is disabled"
  msg 'grep "net\.ipv4\.ip_forward" /etc/sysctl.conf /etc/sysctl.d/*'
  grep "net\.ipv4\.ip_forward" /etc/sysctl.conf /etc/sysctl.d/* 2> /dev/null > /dev/null
  check_retval_eq_0 $?

###3.1.2 Ensure packet redirect sending is disabled
  header "3.1.2 Ensure packet redirect sending is disabled"
  msg 'grep -E "net\.ipv4\.conf\ /etc/sysctl.conf/etc/sysctl.d'
  grep -E "net\.ipv4\.conf\.all\.send_redirects|net\.ipv4\.conf\.default\.send_redirects" /etc/sysctl.conf /etc/sysctl.d/*  2> /dev/null > /dev/null
  check_retval_eq_0 $?

##3.2.1 Ensure source routed packets are not accepted
  header "3.2.1 Ensure source routed packets are not accepted"
  msg 'grep "net\.ipv4\.conf\.all  /etc/sysctl.conf/etc/sysctl.d/*'
  grep -E "net\.ipv4\.conf\.all\.accept_source_route | net\.ipv4\.conf\.default\.accept_source_route" /etc/sysctl.conf /etc/sysctl.d/* 2> /dev/null > /dev/null
  check_retval_eq_0 $?

##3.2.2 Ensure ICMP redirects are not accepted
  header "3.2.2 Ensure ICMP redirects are not accepted"
  msg 'grep "net\.ipv4\.conf\.all\.acc ts" /etc/sysctl.conf/etc/sysctl.d/*'
  grep -E "net\.ipv4\.conf\.all\.accept_redirects | net\.ipv4\.conf\.default\.accept_redirects" /etc/sysctl.conf /etc/sysctl.d/* 2> /dev/null > /dev/null
  check_retval_eq_0 $?

##3.2.3 Ensure secure ICMP redirects are not accepted
  header "3.2.3 Ensure secure ICMP redirects are not accepted"
  msg 'grep "net\.ipv4\.conf\.all\.se c/sysctl.conf/etc/sysctl.d/*'
  grep -E "net\.ipv4\.conf\.all\.secure_redirects | net\.ipv4\.conf\.default\.secure_redirects" /etc/sysctl.conf /etc/sysctl.d/* 2> /dev/null > /dev/null
  check_retval_eq_0 $?

##3.2.4 Ensure suspicious packets are logged
  header "3.2.4 Ensure suspicious packets are logged"
  msg 'grep "net\.ipv4\.conf\.all\.l /sysctl.conf /etc/sysctl.d/*'
  grep -E "net\.ipv4\.conf\.all\.log_martians | net\.ipv4\.conf\.default\.log_martians" /etc/sysctl.conf /etc/sysctl.d/* 2> /dev/null > /dev/null
  check_retval_eq_0 $?

##3.2.5 Ensure broadcast ICMP requests are ignored
  header "3.2.5 Ensure broadcast ICMP requests are ignored"
  msg 'grep "net\.ipv4\.icmp_echo_ig" /etc/sysctl.conf etc/sysctl.d/*' 
  grep "net\.ipv4\.icmp_echo_ignore_broadcasts" /etc/sysctl.conf etc/sysctl.d/* 2> /dev/null > /dev/null
  check_retval_eq_0 $?

##3.2.6 Ensure bogus ICMP responses are ignored
  header "3.2.6 Ensure bogus ICMP responses are ignored"
  msg 'grep "net\.ipv4\.icmp_ig /etc/sysctl.conf /etc/sysctl.d/*'
  grep "net\.ipv4\.icmp_ignore_bogus_error_responses" /etc/sysctl.conf /etc/sysctl.d/* 2> /dev/null > /dev/null
  check_retval_eq_0 $?

##3.2.7 Ensure Reverse Path Filtering is enabled
  header "3.2.7 Ensure Reverse Path Filtering is enabled"
  msg 'grep "net\.ipv4\. /etc/sysctl.conf /etc/sysctl.d/*'
  grep -E "net\.ipv4\.conf\.all\.rp_filter | net\.ipv4\.conf\.default\.rp_filter" /etc/sysctl.conf /etc/sysctl.d/* 2> /dev/null > /dev/null
  check_retval_eq_0 $? 

##3.2.8 Ensure TCP SYN Cookies is enabled
  header "3.2.8 Ensure TCP SYN Cookies is enabled"
  msg 'grep "net\.ipv4\.tcp /etc/sysctl.conf /etc/sysctl.d/*'
  grep "net\.ipv4\.tcp_syncookies" /etc/sysctl.conf /etc/sysctl.d/* 2> /dev/null > /dev/null
  check_retval_eq_0 $?

##3.4.1 Ensure TCP Wrappers is installed
  header "3.4.1 Ensure TCP Wrappers is installed" 
  msg 'dpkg -s tcpd'
  dpkg -s tcpd 2> /dev/null > /dev/null
  check_retval_eq_0 $?

##3.4.2 Ensure /etc/hosts.allow is configured
  header "3.4.2 Ensure /etc/hosts.allow is configured"
  msg "cat /etc/hosts.allow"
  grep "ALL:" /etc/hosts.allow 2>&1 > /dev/null
  check_retval_eq_0 $?

##3.4.3 Ensure /etc/hosts.deny is configured
  header "3.4.3 Ensure /etc/hosts.deny is configured"
  msg "cat /etc/hosts.deny"
  grep "ALL: ALL" /etc/hosts.deny 2>&1 > /dev/null
  check_retval_eq_0 $?

##3.4.4 Ensure permissions on /etc/hosts.allow are configured
  header "3.4.4 Ensure permissions on /etc/hosts.allow are configured"
  msg "Ensure /etc/hosts.allow permissions are 0644 root:root"
    if [[ $(stat /etc/hosts.allow) =~ Access:.*(0644/-rw-r--r--).*Uid:.*(.*0/.*root).*Gid:.*(.*0/.*root) ]];then
        success_result
    else
        failed_result
    fi

##3.4.5 Ensure permissions on /etc/hosts.deny are configured
  header "3.4.5 Ensure permissions on /etc/hosts.deny are configured"
  msg "Ensure /etc/hosts.deny permissions are 0644 root:root"
    if [[ $(stat /etc/hosts.deny) =~ Access:.*(0644/-rw-r--r--).*Uid:.*(.*0/.*root).*Gid:.*(.*0/.*root) ]];then
        success_result
    else
        failed_result
    fi

##3.6.1 Ensure iptables is installed
  header "3.6.1 Ensure iptables is installed"
  msg 'dpkg -s iptables'
  dpkg -s iptables 2> /dev/null > /dev/null
  check_retval_eq_0 $?

##3.6.2 Ensure default deny firewall policy
  header "3.6.2 Ensure default deny firewall policy"
  msg 'iptables -L | grep "Chain" | grep "policy ACCEPT"'
  iptables -L 2> /dev/null | grep "Chain" | grep "policy ACCEPT"  > /dev/null
  check_retval_ne_0 $?

###3.6.3 Ensure loopback traffic is configured
  header "3.6.3 Ensure loopback traffic is configured"
  msg 'iptables -L INPUT and OUTPUT -v -n'
  if [[ $(iptables -L INPUT -v -n) =~ .*ACCEPT.*all.*--.*lo.*0.0.0.0/0.*0.0.0.0/0  ]];then
	 if [[ $(iptables -L INPUT -v -n) =~ .*DROP.*all.*--.*127.0.0.0/8.*0.0.0.0/0  ]];then

         	if [[ $(iptables -L INPUT -v -n) =~ .*ACCEPT.*all.*--.*lo.*0.0.0.0/0.*0.0.0.0/0  ]]; then

		          success_result
      		else

       			failed_result
                fi
         else
 		failed_result
         fi
  else
 		failed_result	  
  fi

##3.6.5 Ensure firewall rules exist for all open ports
  header "3.6.5 Ensure firewall rules exist for all open ports"
  netstat -ln |grep -vE "tcp6|udp6|unix|UNIX|RefCnt|Active" | tr -s " " | cut -d " " -f4 | grep -v Local | cut -d ":" -f2 > /tmp/open_port
  for i in $(cat /tmp/open_port)
  do
        iptables -L INPUT -v -n | grep dpt:$i > /dev/null
        if [ $? -ne 0 ]; then
		msg "iptables -L INPUT -v -n | grep dpt:$i"
		failed_result
	else
		msg "iptables -L INPUT -v -n | grep dpt:$i"
		success_result
        fi	
  done

##4.1.1.1 Ensure audit log storage size is configured
  header "4.1.1.1 Ensure audit log storage size is configured"
  msg 'grep max_log_file /etc/audit/auditd.conf'
  grep max_log_file /etc/audit/auditd.conf 2> /dev/null > /dev/null
  check_retval_eq_0 $?

##4.1.1.2 Ensure system is disabled when audit logs are full
  header "4.1.1.2 Ensure system is disabled when audit logs are full"
  msg 'grep admin_space_left_action /etc/audit/auditd.conf'
  grep admin_space_left_action /etc/audit/auditd.conf 2> /dev/null > /dev/null
  check_retval_eq_0 $?

##4.1.1.3 Ensure audit logs are not automatically deleted
  header "4.1.1.3 Ensure audit logs are not automatically deleted"
  msg 'grep max_log_file_action /etc/audit/auditd.conf'
  grep max_log_file_action /etc/audit/auditd.conf 2> /dev/null > /dev/null
  check_retval_eq_0 $?

##4.1.2 Ensure auditd service is enabled
  header "4.1.2 Ensure auditd service is enabled"
  msg 'systemctl is-enabled auditd'
  systemctl is-enabled auditd 2> /dev/null > /dev/null
  check_retval_eq_0 $?

##4.1.3 Ensure auditing for processes that start prior to auditd is enabled
  header "4.1.3 Ensure auditing for processes that start prior to auditd is enabled"
  msg 'grep "^\s*linux" /boot/grub/grub.cfg'
  grep "^\s*linux" /boot/grub/grub.cfg 2> /dev/null | grep "audit=1"  > /dev/null
  check_retval_eq_0 $?

##4.1.4 Ensure events that modify date and time information are collected
 header "4.1.4 Ensure events that modify date and time information are collected"
 msg 'grep time-change /etc/audit/audit.rules'
 grep time-change /etc/audit/audit.rules 2> /dev/null > /dev/null
 check_retval_eq_0 $?

##4.1.5 Ensure events that modify user/group information are collected
  header "4.1.5 Ensure events that modify user/group information are collected"
  msg 'grep identity /etc/audit/audit.rules'
  grep identity /etc/audit/audit.rules 2> /dev/null > /dev/null
  check_retval_eq_0 $?

##4.1.6 Ensure events that modify the system's network environment are collected  
  header "4.1.6 Ensure events that modify the system's network environment are collected"
  msg 'grep system-locale /etc/audit/audit.rules'
  grep system-locale /etc/audit/audit.rules 2> /dev/null > /dev/null
  check_retval_eq_0 $?

##4.1.7 Ensure events that modify the system's Mandatory Access Controls are collected
  header "##4.1.7 Ensure events that modify the system's Mandatory Access Controls are collected"
  msg 'grep MAC-policy /etc/audit/audit.rules'
  grep MAC-policy /etc/audit/audit.rules 2> /dev/null > /dev/null
  check_retval_eq_0 $?

##4.1.8 Ensure login and logout events are collected
  header "4.1.8 Ensure login and logout events are collected"
  msg 'grep logins /etc/audit/audit.rules'
  grep logins /etc/audit/audit.rules 2> /dev/null > /dev/null
  check_retval_eq_0 $?

##4.1.9 Ensure session initiation information is collected
  header "4.1.9 Ensure session initiation information is collected"
  msg 'grep session /etc/audit/audit.rules'
  grep session /etc/audit/audit.rules 2> /dev/null > /dev/null
  check_retval_eq_0 $?

##4.1.10 Ensure discretionary access control permission modification events are collected
  header "4.1.10 Ensure discretionary access control permission modification events are collected"
  msg 'grep perm_mod /etc/audit/audit.rules'
  grep perm_mod /etc/audit/audit.rules 2> /dev/null > /dev/null
  check_retval_eq_0 $?

##4.1.11 Ensure unsuccessful unauthorized file access attempts are collected
  header "4.1.11 Ensure unsuccessful unauthorized file access attempts are collected"
  msg 'grep access /etc/audit/audit.rules'
  grep access /etc/audit/audit.rules 2> /dev/null > /dev/null
  check_retval_eq_0 $?

##4.1.12 Ensure use of privileged commands is collected
##   header "4.1.12 Ensure use of privileged commands is collected"
##   msg ''
##4.1.13 Ensure successful file system mounts are collected
   header "4.1.13 Ensure successful file system mounts are collected"
   msg 'grep mounts /etc/audit/audit.rules'
   grep mounts /etc/audit/audit.rules 2> /dev/null > /dev/null
   check_retval_eq_0 $?

##4.1.14 Ensure file deletion events by users are collected
  header "4.1.14 Ensure file deletion events by users are collected"
  msg 'grep delete /etc/audit/audit.rules'
  grep delete /etc/audit/audit.rules 2> /dev/null > /dev/null
  check_retval_eq_0 $?
 
##4.1.15 Ensure changes to system administration scope (sudoers) is collected
  header "4.1.15 Ensure changes to system administration scope (sudoers) is collected"
  msg 'grep scope /etc/audit/audit.rules'
  grep scope /etc/audit/audit.rules 2> /dev/null > /dev/null
  check_retval_eq_0 $?

##4.1.16 Ensure system administrator actions (sudolog) are collected
  header "4.1.16 Ensure system administrator actions (sudolog) are collected"
  msg 'grep actions /etc/audit/audit.rules' 
  grep actions /etc/audit/audit.rules 2> /dev/null > /dev/null
  check_retval_eq_0 $?

##4.1.17 Ensure kernel module loading and unloading is collected
  header "4.1.17 Ensure kernel module loading and unloading is collected"
  msg 'grep modules /etc/audit/audit.rules' 
  grep modules /etc/audit/audit.rules 2> /dev/null > /dev/null
  check_retval_eq_0 $?

##4.1.18 Ensure the audit configuration is immutable
  header "4.1.18 Ensure the audit configuration is immutable"
  msg 'grep "^\s*[^#]" /etc/audit/audit.rules | tail -1'
  grep "^\s*[^#]" /etc/audit/audit.rules 2> /dev/null | tail -1 > /dev/null 
  check_retval_eq_0 $?

##4.2.1.1 Ensure rsyslog Service is enabled
  header "4.2.1.1 Ensure rsyslog Service is enabled"
  msg 'systemctl is-enabled rsyslog'
  systemctl is-enabled rsyslog 2> /dev/null | grep enabled > /dev/null
  check_retval_eq_0 $?

##4.2.1.3 Ensure rsyslog default file permissions configured
  header "4.2.1.3 Ensure rsyslog default file permissions configured"
  msg 'grep ^\$FileCreateMode /etc/rsyslog.conf /etc/rsyslog.d/*.conf'
  grep "^\$FileCreateMode 0640" /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2> /dev/null > /dev/null
  check_retval_eq_0 $?

##4.2.1.4 Ensure rsyslog is configured to send logs to a remote log host
 header "4.2.1.4 Ensure rsyslog is configured to send logs to a remote log host"
 msg 'grep "^*.*[^I][^I]*@" /etc/rsyslog.conf /etc/rsyslog.d/*.conf' 2> /dev/null > /dev/null
 check_retval_eq_0 $? 

##4.2.2.1 Ensure syslog-ng service is enabled
  header "4.2.2.1 Ensure syslog-ng service is enabled"
  msg 'systemctl is-enabled syslog-ng'
  systemctl is-enabled syslog-ng 2> /dev/null | grep enabled > /dev/null
  check_retval_eq_0 $?

##4.2.2.3 Ensure syslog-ng default file permissions configured
  header "4.2.2.3 Ensure syslog-ng default file permissions configured"
  msg 'grep ^options /etc/syslog-ng/syslog-ng.conf'
  grep ^options /tmp/syslog-ng.conf 2> /dev/null | grep "perm(0640)" > /dev/null
  check_retval_eq_0 $?

##4.2.3 Ensure rsyslog or syslog-ng is installed
  header "4.2.3 Ensure rsyslog or syslog-ng is installed"
  msg ' dpkg -s rsyslog | syslog-ng'
  if [ `dpkg -s rsyslog 2> /dev/null | echo $?` -eq 0  ] || [ `dpkg -s syslog-ng 2> /dev/null  | echo $?` -eq 0 ]; then
	  success_result
  else
	  failed_result
  fi

##4.2.4 Ensure permissions on all logfiles are configured
  header "4.2.4 Ensure permissions on all logfiles are configured"
  msg 'find /var/log -type f -ls'
  other=`find /var/log -type f -ls | tr -s " " | cut -d " " -f4 | cut -c8-10 | grep -E "r|w|x" > /dev/null; echo $?`
  group=`find /var/log -type f -ls | tr -s " " | cut -d " " -f4 | cut -c5-7 | grep -E "w|x" > /dev/null; echo $?`

  if [ $other -ne 0 -a $group -ne 0 ]; then
	  success_result
  else
          failed_result
  fi

##5.1.1 Ensure cron daemon is enabled
  msg 'systemctl is-enabled crond'
  systemctl is-enabled cron | grep enabled 2>&1 > /dev/null
  check_retval_eq_0 $?

##5.1.2 Ensure permissions on /etc/crontab are configured
  header "5.1.2 Ensure permissions on /etc/crontab are configured"
  msg "Ensure /etc/crontab permissions are 0600 root:root"
    if [[ $(stat -L -c "%a %U %G" /etc/crontab) == "600 root root" ]];then
        success_result
    else
        failed_result
    fi

##5.1.3 Ensure permissions on /etc/cron.hourly are configured
  msg "Ensure /etc/cron.hourly permissions are 0600 root:root"
    if [[ $(stat -L -c "%a %U %G" /etc/cron.hourly) == "600 root root" ]];then
        success_result
    else
        failed_result
    fi
##5.1.4 Ensure permissions on /etc/cron.daily are configured
  msg "Ensure /etc/cron.daily permissions are 0600 root:root"
    if [[ $(stat -L -c "%a %U %G" /etc/cron.daily) == "600 root root" ]];then
        success_result
    else
        failed_result
    fi

##5.1.5 Ensure permissions on /etc/cron.weekly are configured
  msg "Ensure /etc/cron.weekly permissions are 0600 root:root"
    if [[ $(stat -L -c "%a %U %G" /etc/cron.weekly) == "600 root root" ]];then
        success_result
    else
        failed_result
    fi

##5.1.6 Ensure permissions on /etc/cron.monthly are configured
  msg "Ensure /etc/cron.monthly permissions are 0600 root:root"
    if [[ $(stat -L -c "%a %U %G" /etc/cron.monthly) == "600 root root" ]];then
        success_result
    else
        failed_result
    fi

##5.1.7 Ensure permissions on /etc/cron.d are configured
  header "5.1.7 Ensure permissions on /etc/cron.d are configured"
  msg "Ensure /etc/cron.d permissions are 0600 root:root"
    if [[ $(stat -L -c "%a %U %G" /etc/cron.d) == "600 root root" ]];then
        success_result
    else
        failed_result
    fi

##5.1.8 Ensure at/cron is restricted to authorized users
  header "5.1.8 Ensure at/cron is restricted to authorized users"
  msg "Ensure /etc/cron.deny doesn't exist"
    if [ -f /etc/cron.deny ];then
      failed_result
    else
      success_result
    fi
    msg "Ensure /etc/at.deny doesn't exist"
    if [ -f /etc/at.deny ];then
      failed_result
    else
      success_result
    fi
##5.2.1 Ensure permissions on /etc/ssh/sshd_config are configured
 header "5.2.1 Ensure permissions on /etc/ssh/sshd_config are configured"
 msg "Ensure /etc/ssh/sshd_config permissions are 0600 root:root"
    if [[ $(stat /etc/ssh/sshd_config) =~ Access:.*(0600/-rw-------).*Uid:.*(.*0/.*root).*Gid:.*(.*0/.*root) ]];then
        success_result
    else
        failed_result
    fi

##5.2.2 Ensure SSH Protocol is set to 2
  header "5.2.2 Ensure SSH Protocol is set to 2"
  msg 'grep "^Protocol" /etc/ssh/sshd_config | grep "2"'
  grep "^Protocol" /etc/ssh/sshd_config | grep "2" 2>&1 > /dev/null
  check_retval_eq_0 $?

##5.2.3 Ensure SSH LogLevel is set to INFO
  header "5.2.3 Ensure SSH LogLevel is set to INFO"
  msg 'grep "^LogLevel" /etc/ssh/sshd_config | grep "INFO"'
  grep "^LogLevel" /etc/ssh/sshd_config | grep "INFO" 2>&1 > /dev/null
  check_retval_eq_0 $?

##5.2.4 Ensure SSH X11 forwarding is disabled
  header "5.2.4 Ensure SSH X11 forwarding is disabled"
  msg 'grep "^X11Forwarding" /etc/ssh/sshd_config  | grep "no"'
  grep "^X11Forwarding" /etc/ssh/sshd_config  | grep "no" 2>&1 > /dev/null
  check_retval_eq_0 $?

##5.2.5 Ensure SSH MaxAuthTries is set to 4 or less
  header "5.2.5 Ensure SSH MaxAuthTries is set to 4 or less"
  msg 'grep "^MaxAuthTries" /etc/ssh/sshd_config | grep "4"'
    if [[ $(grep "^MaxAuthTries" /etc/ssh/sshd_config | awk '{print $2}') -le 4 ]];then
      success_result
    else
      failed_result
    fi

##5.2.6 Ensure SSH IgnoreRhosts is enabled
  header "5.2.6 Ensure SSH IgnoreRhosts is enabled"
  msg 'grep "^IgnoreRhosts" /etc/ssh/sshd_config | grep "yes"'
  grep "^IgnoreRhosts" /etc/ssh/sshd_config | grep "yes" 2>&1 > /dev/null
  check_retval_eq_0 $?

##5.2.7 Ensure SSH HostbasedAuthentication is disabled
  header "5.2.7 Ensure SSH HostbasedAuthentication is disabled"
  msg 'grep "^HostbasedAuthentication" /etc/ssh/sshd_config | grep "no"'
  grep "^HostbasedAuthentication" /etc/ssh/sshd_config | grep "no" 2>&1 > /dev/null
  check_retval_eq_0 $?

##5.2.8 Ensure SSH root login is disabled
  header "5.2.8 Ensure SSH root login is disabled"
  msg 'grep "^PermitRootLogin" /etc/ssh/sshd_config | grep no'
  grep "^PermitRootLogin" /etc/ssh/sshd_config | grep "no" 2>&1 > /dev/null
  check_retval_eq_0 $?

##5.2.9 Ensure SSH PermitEmptyPasswords is disabled
  header "5.2.9 Ensure SSH PermitEmptyPasswords is disabled"
  msg 'grep "^PermitEmptyPasswords" /etc/ssh/sshd_config | grep "no"'
  grep "^PermitEmptyPasswords" /etc/ssh/sshd_config | grep "no" 2>&1 > /dev/null
  check_retval_eq_0 $?

##5.2.10 Ensure SSH PermitUserEnvironment is disabled
  header "5.2.10 Ensure SSH PermitUserEnvironment is disabled"
  msg 'grep PermitUserEnvironment /etc/ssh/sshd_config | grep "no"'
  grep PermitUserEnvironment /etc/ssh/sshd_config | grep "no" 2>&1 > /dev/null
  check_retval_eq_0 $?

##5.2.11 Ensure only approved MAC algorithms are used
  header "5.2.11 Ensure only approved ciphers are used"
  msg 'grep "Ciphers" /etc/ssh/sshd_config'
  grep "Ciphers" /etc/ssh/sshd_config 2>&1 > /dev/null
  check_retval_eq_0 $?

##5.2.12 Ensure SSH Idle Timeout Interval is configured
  header "5.2.12 Ensure only approved MAC algorithms are used"
  msg 'grep "MACs" /etc/ssh/sshd_config'
  grep "MACs" /etc/ssh/sshd_config 2>&1 > /dev/null
  check_retval_eq_0 $?

##5.2.13 Ensure SSH LoginGraceTime is set to one minute or less
  header "5.2.13 Ensure SSH Idle Timeout Interval is configured"
    msg 'grep "^ClientAliveInterval" /etc/ssh/sshd_config'
    if [[ $(grep "^ClientAliveInterval" /etc/ssh/sshd_config | awk '{print $2}') -le 300 ]];then
      success_result
    else
      failed_result
    fi
    msg 'grep "^ClientAliveCountMax" /etc/ssh/sshd_config '
    if [[ $(grep "^ClientAliveCountMax" /etc/ssh/sshd_config  | awk '{print $2}') -le 3 ]];then
      success_result
    else
      failed_result
    fi
  


   ##############
#FINAL REPORT
##############
for (( x=0; x < $(($WIDTH+1)); x++));do
    printf %s '='
done
printf "\n"
printf "%$(($WIDTH - 4))s" "TOTAL CHECKS: "
printf "%4s\n" "$(($PASSED_CHECKS + $FAILED_CHECKS))"
printf "%$(($WIDTH - 4))s" "FAILED CHECKS: "
printf "%4s\n" "$FAILED_CHECKS"
printf "%$(($WIDTH - 4))s" "PASSED CHECKS: "
printf "%4s\n" "$PASSED_CHECKS"

