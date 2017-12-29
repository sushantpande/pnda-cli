#!/bin/bash -v

set -ex

cat << EOF > /etc/modprobe.d/hardening.conf
install cramfs /bin/true
install feevxfs /bin/true
install jffs2 /bin/true
install hfs /bin/true
install hfsplus /bin/true
install squashfs /bin/true
install udf /bin/true
install dccp /bin/true
install sctp /bin/true
install rds /bin/true
install tipc /bin/true
install usb-storage /bin/true
install net-pf-31 /bin/true
install bluetooth /bin/true
EOF

yum remove -y setroubleshoot mcstrans telnet-server rsh-server rsh ypbind ypserv tftp tftp-server talk talk-server xinetd dhcp bind vsftpd httpd dovecot samba squid net-snmp
yum install -y tcp_wrappers screen rsyslog ed vim vim-enhanced

chown root:root /boot/grub2/grub.cfg
chmod og-rwx /boot/grub2/grub.cfg
echo -e 'highlysecure\nhighlysecure' | grub2-mkpasswd-pbkdf2
sed -i 's/--unrestricted//g' /boot/grub2/grub.cfg

echo "*  hard  core  0" >> /etc/sysctl.conf
cat << EOF >> /etc/sysctl.conf
fs.suid_dumpable = 0
kernel.exec-shield = 1
kernel.randomize_va_space = 2
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
EOF

sed -i "/SINGLE/s/sushell/sulogin/" /etc/sysconfig/init
sed -i "/PROMPT/s/yes/no/" /etc/sysconfig/init

sed -i "/^vc/d" /etc/securetty

echo " umask 027" >> /etc/sysconfig/init

cat << EOF >> /etc/sysconfig/network
NETWORKING_IPV6=no
IPV6INIT=no
EOF
cat << EOF >> /etc/modprobe.d/ipv6.conf
options ipv6 disable=1
EOF

cat << EOF >> /etc/hosts.deny
ALL: ALL
EOF

cat << EOF >> /etc/hosts.allow
sshd: ALL
postfix: localhost
rpcbind: localhost
EOF

chmod 644 /etc/hosts.allow
chown root:root /etc/hosts.allow
chmod 644 /etc/hosts.deny
chown root:root /etc/hosts.deny


cat << EOF > /etc/rsyslog.conf
#Use traditional timestamp format
\$ActionFileDefaultTemplate RSYSLOG_TraditionalFileFormat

# Provides kernel logging support (previously done by rklogd)
\$ModLoad imklog
# Provides support for local system logging (e.g. via logger command)
\$ModLoad imuxsock
\$CreateDirs on
\$DirCreateMode 0755
\$WorkDirectory /var/log/rsyslog
\$ActionQueueType LinkedList
\$ActionQueueFileName rsyslog
\$ActionQueueMaxDiskSpace 1g
\$ActionResumeRetryCount -1
\$ActionQueueSaveOnShutdown on
*.*                                                     @ or @@syslog ip
*.*                                                     @ or @@syslog ip

#### RULES ####

# Log all kernel messages to the console.
# Logging much else clutters up the screen.
#kern.*                                                 /dev/console

# Log anything (except mail) of level info or higher.
# Don't log private authentication messages!
*.info;mail.none;authpriv.none;cron.none                /var/log/messages

# The authpriv file has restricted access.
authpriv.*                                              /var/log/secure

# Log all the mail messages in one place.
mail.*                                                  -/var/log/maillog


# Log cron stuff
cron.*                                                  /var/log/cron

# Everybody gets emergency messages
*.emerg                                                 *

# Save news errors of level crit and higher in a special file.
uucp,news.crit                                          /var/log/spooler

# Save boot messages also to boot.log
local7.*                                                /var/log/boot.log
EOF

cd /var/log
mkdir rsyslog
chown root:root messages secure maillog cron spooler boot.log rsyslog
chmod og-rwx messages secure maillog cron spooler boot.log rsyslog
systemctl restart rsyslog


sed -i "/^space_left_action/d" /etc/audit/auditd.conf
sed -i "/^admin_space_left_action/d" /etc/audit/auditd.conf
sed -i "/^max_log_file/d" /etc/audit/auditd.conf
sed -i "/^max_log_file_action/d" /etc/audit/auditd.conf

cat << EOF >> /etc/audit/auditd.conf
space_left_action = SYSLOG
admin_space_left_action = SYSLOG
max_log_file = 1000
max_log_file_action = keep_logs
EOF

mkdir /usr/local/scripts

cat << EOF > /usr/local/scripts/auditd.cron
#!/bin/sh

##########
# This script can be installed to get a daily log rotation
# based on a cron job.
##########
YDATE=\`date -d '1 day ago' +%Y%m%d\`
/sbin/service auditd rotate
mv /var/log/audit/audit.log.1 /var/log/audit/audit.log.`hostname -s`-\$YDATE
xz /var/log/audit/audit.log.`hostname -s`-\$YDATE
EXITVALUE=\$?
if [ \$EXITVALUE != 0 ]; then
    /usr/bin/logger -t auditd "ALERT exited abnormally with [\$EXITVALUE]"
fi
exit 0
EOF

chmod 750 /usr/local/scripts/auditd.cron

#crontab -l > root_crontab
echo "0 0 * * * /usr/local/scripts/auditd.cron > /dev/null 2>&1" >> root_crontab
crontab root_crontab
rm root_crontab

cp /etc/audit/audit.rules /etc/audit/audit.rules.backup
#cp /usr/share/doc/audit-version/stig.rules /etc/audit/audit.rules


cat << EOF > /etc/audit/audit.rules
## This file contains the auditctl rules that are loaded
## whenever the audit daemon is started via the initscripts.
## The rules are simply the parameters that would be passed
## to auditctl.
##
## First rule - delete all
-D

## Increase the buffers to survive stress events.
## Make this bigger for busy systems
-b 8192

## Set failure mode to panic
-f 2

## NOTE:
## 1) if this is being used on a 32 bit machine, comment out the b64 lines
## 2) These rules assume that login under the root account is not allowed.
## 3) It is also assumed that 500 represents the first usable user account. To
##    be sure, look at UID_MIN in /etc/login.defs.
## 4) If these rules generate too much spurious data for your tastes, limit the
## the syscall file rules with a directory, like -F dir=/etc
## 5) You can search for the results on the key fields in the rules
##
##
## (GEN002880: CAT II) The IAO will ensure the auditing software can
## record the following for each audit event: 
##- Date and time of the event 
##- Userid that initiated the event 
##- Type of event 
##- Success or failure of the event 
##- For I&A events, the origin of the request (e.g., terminal ID) 
##- For events that introduce an object into a user’s address space, and
##  for object deletion events, the name of the object, and in MLS
##  systems, the object’s security level.
##
## Things that could affect time
-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -F auid!=-1 -F uid!=ntp -k time-change
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -F auid!=-1 -F uid!=ntp -k time-change
-a always,exit -F arch=b32 -S clock_settime -F a0=0 -F auid!=-1 -F uid!=ntp -k time-change
-a always,exit -F arch=b64 -S clock_settime -F a0=0 -F auid!=-1 -F uid!=ntp -k time-change
# Introduced in 2.6.39, commented out because it can make false positives
#-a always,exit -F arch=b32 -S clock_adjtime -k time-change
#-a always,exit -F arch=b64 -S clock_adjtime -k time-change
-w /etc/localtime -p wa -k time-change

## Things that affect identity
-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity

## Things that could affect system locale
-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale
-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale
-w /etc/issue -p wa -k system-locale
-w /etc/issue.net -p wa -k system-locale
-w /etc/hosts -p wa -k system-locale
-w /etc/sysconfig/network -p wa -k system-locale

## Things that could affect MAC policy
-w /etc/selinux/ -p wa -k MAC-policy


## (GEN002900: CAT III) The IAO will ensure audit files are retained at
## least one year; systems containing SAMI will be retained for five years.
##
## Site action - no action in config files

## (GEN002920: CAT III) The IAO will ensure audit files are backed up
## no less than weekly onto a different system than the system being
## audited or backup media.  
##
## Can be done with cron script

## (GEN002700: CAT I) (Previously – G095) The SA will ensure audit data
## files have permissions of 640, or more restrictive.
##
## Done automatically by auditd

## (GEN002720-GEN002840: CAT II) (Previously – G100-G106) The SA will
## configure the auditing system to audit the following events for all
## users and root:
##
## - Logon (unsuccessful and successful) and logout (successful)
##
## Handled by pam, sshd, login, and gdm
## Might also want to watch these files if needing extra information
-w /var/log/tallylog -p wa -k logins
-w /var/run/faillock/ -p wa -k logins
-w /var/log/lastlog -p wa -k logins


##- Process and session initiation (unsuccessful and successful)
##
## The session initiation is audited by pam without any rules needed.
## Might also want to watch this file if needing extra information
-w /var/run/utmp -p wa -k session
-w /var/log/btmp -p wa -k session
-w /var/log/wtmp -p wa -k session

##- Discretionary access control permission modification (unsuccessful
## and successful use of chown/chmod)
-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=500 -F auid!=4294967295 -k perm_mod

##- Unauthorized access attempts to files (unsuccessful) 
-a always,exit -F arch=b32 -S creat -S open -S openat -S open_by_handle_at -S truncate -F exit=-EACCES -F auid>=500 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S creat -S open -S openat -S open_by_handle_at -S truncate -F exit=-EPERM -F auid>=500 -F auid!=4294967295 -k access
-a always,exit -F arch=b64 -S creat -S open -S openat -S open_by_handle_at -S truncate -F exit=-EACCES -F auid>=500 -F auid!=4294967295 -k access
-a always,exit -F arch=b64 -S creat -S open -S openat -S open_by_handle_at -S truncate -F exit=-EPERM -F auid>=500 -F auid!=4294967295 -k access

##- Use of privileged commands (unsuccessful and successful)
## use find /bin -type f -perm -04000 2>/dev/null and put all those files in a rule like this
(Run find / -xdev \( -perm -4000 -o -perm -2000 \) -type f | awk '{print "-a always,exit -F path=" \$1 " -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged" }' and add output to file after privilaged commands comment)


##- Use of print command (unsuccessful and successful) 

##- Export to media (successful)
## You have to mount media before using it. You must disable all automounting
## so that its done manually in order to get the correct user requesting the
## export
-a always,exit -F arch=b32 -S mount -F auid>=500 -F auid!=4294967295 -k export
-a always,exit -F arch=b64 -S mount -F auid>=500 -F auid!=4294967295 -k export

##- System startup and shutdown (unsuccessful and successful)

##- Files and programs deleted by the user (successful and unsuccessful)
-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=500 -F auid!=4294967295 -k delete
-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=500 -F auid!=4294967295 -k delete

##- All system administration actions 
##- All security personnel actions
## 
## Look for pam_tty_audit and add it to your login entry point's pam configs.
## If that is not found, use sudo which should be patched to record its
## commands to the audit system. Do not allow unrestricted root shells or
## sudo cannot record the action.
-w /etc/sudoers -p wa -k actions

## (GEN002860: CAT II) (Previously – G674) The SA and/or IAO will
##ensure old audit logs are closed and new audit logs are started daily.
##
## Site action. Can be assisted by a cron job

## Not specifically required by the STIG; but common sense items
## Optional - could indicate someone trying to do something bad or
## just debugging
#-a always,exit -F arch=b32 -S ptrace -k tracing
#-a always,exit -F arch=b64 -S ptrace -k tracing
#-a always,exit -F arch=b32 -S ptrace -F a0=4 -k code-injection
#-a always,exit -F arch=b64 -S ptrace -F a0=4 -k code-injection
#-a always,exit -F arch=b32 -S ptrace -F a0=5 -k data-injection
#-a always,exit -F arch=b64 -S ptrace -F a0=5 -k data-injection
#-a always,exit -F arch=b32 -S ptrace -F a0=6 -k register-injection
#-a always,exit -F arch=b64 -S ptrace -F a0=6 -k register-injection

## Optional - might want to watch module insertion
-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
#-a always,exit -F arch=b32 -S init_module -S finit_module -k module-load
#-a always,exit -F arch=b64 -S init_module -S finit_module -k module-load
-a always,exit -F arch=b32 -S delete_module -k module-unload
-a always,exit -F arch=b64 -S delete_module -k module-unload

## Optional - admin may be abusing power by looking in user's home dir
#-a always,exit -F dir=/home -F uid=0 -F auid>=500 -F auid!=4294967295 -C auid!=obj_uid -F key=power-abuse

## Optional - log container creation  
#-a always,exit -F arch=b32 -S clone -F a0&2080505856 -k container-create
#-a always,exit -F arch=b64 -S clone -F a0&2080505856 -k container-create

## Optional - watch for containers that may change their configuration 
#-a always,exit -F arch=b32 -S setns -S unshare -k container-config
#-a always,exit -F arch=b64 -S setns -S unshare -k container-config

## Put your own watches after this point
# -w /your-file -p rwxa -k mykey

## Make the configuration immutable - reboot is required to change audit rules
-e 2
EOF

service auditd restart

chown root:root /etc/crontab /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/cron.d
chmod og-rwx /etc/crontab /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/cron.d
rm -f /etc/at.deny /etc/cron.deny
touch /etc/at.allow
echo "root" > /etc/cron.allow
chown root:root /etc/at.allow /etc/cron.allow
chmod og-rwx /etc/at.allow /etc/cron.allow
systemctl restart crond.service


cat << EOF > /etc/ssh/sshd_config
#       \$OpenBSD: sshd_config,v 1.80 2008/07/02 02:24:18 djm Exp \$

# This is the sshd server system-wide configuration file.  See
# sshd_config(5) for more information.

# This sshd was compiled with PATH=/usr/local/bin:/bin:/usr/bin

# The strategy used for options in the default sshd_config shipped with
# OpenSSH is to specify options with their default value where
# possible, but leave them commented.  Uncommented options change a
# default value.

Port 22
#AddressFamily any
#ListenAddress 0.0.0.0
#ListenAddress ::

# Disable legacy (protocol version 1) support in the server for new
# installations. In future the default will change to require explicit
# activation of protocol 1
Protocol 2

# HostKey for protocol version 1
#HostKey /etc/ssh/ssh_host_key
# HostKeys for protocol version 2
#HostKey /etc/ssh/ssh_host_rsa_key
#HostKey /etc/ssh/ssh_host_dsa_key

# Lifetime and size of ephemeral version 1 server key
#KeyRegenerationInterval 1h
#ServerKeyBits 1024

# Logging
# obsoletes QuietMode and FascistLogging
#SyslogFacility AUTH
SyslogFacility AUTHPRIV
LogLevel VERBOSE

# Authentication:

#LoginGraceTime 2m
PermitRootLogin no
StrictModes yes
MaxAuthTries 4
#MaxSessions 10

#RSAAuthentication yes
#PubkeyAuthentication yes
#AuthorizedKeysFile     .ssh/authorized_keys
#AuthorizedKeysCommand none
#AuthorizedKeysCommandRunAs nobody

# For this to work you will also need host keys in /etc/ssh/ssh_known_hosts
RhostsRSAAuthentication no
# similar for protocol version 2
HostbasedAuthentication no
# Change to yes if you don't trust ~/.ssh/known_hosts for
# RhostsRSAAuthentication and HostbasedAuthentication
#IgnoreUserKnownHosts no
# Don't read the user's ~/.rhosts and ~/.shosts files
IgnoreRhosts yes

# To disable tunneled clear text passwords, change to no here!
#PasswordAuthentication yes
PermitEmptyPasswords no
PasswordAuthentication yes

# Change to no to disable s/key passwords
#ChallengeResponseAuthentication yes
ChallengeResponseAuthentication no

# Kerberos options
#KerberosAuthentication no
#KerberosOrLocalPasswd yes
#KerberosTicketCleanup yes
#KerberosGetAFSToken no
#KerberosUseKuserok yes

# GSSAPI options
#GSSAPIAuthentication no
GSSAPIAuthentication yes
#GSSAPICleanupCredentials yes
GSSAPICleanupCredentials yes
#GSSAPIStrictAcceptorCheck yes
#GSSAPIKeyExchange no

# Set this to 'yes' to enable PAM authentication, account processing, 
# and session processing. If this is enabled, PAM authentication will 
# be allowed through the ChallengeResponseAuthentication and
# PasswordAuthentication.  Depending on your PAM configuration,
# PAM authentication via ChallengeResponseAuthentication may bypass
# the setting of "PermitRootLogin without-password".
# If you just want the PAM account and session checks to run without
# PAM authentication, then enable this but set PasswordAuthentication
# and ChallengeResponseAuthentication to 'no'.
#UsePAM no
UsePAM yes

# Accept locale-related environment variables
AcceptEnv LANG LC_CTYPE LC_NUMERIC LC_TIME LC_COLLATE LC_MONETARY LC_MESSAGES
AcceptEnv LC_PAPER LC_NAME LC_ADDRESS LC_TELEPHONE LC_MEASUREMENT
AcceptEnv LC_IDENTIFICATION LC_ALL LANGUAGE
AcceptEnv XMODIFIERS

#AllowAgentForwarding yes
AllowTcpForwarding no
#GatewayPorts no
#X11Forwarding no
X11Forwarding no
#X11DisplayOffset 10
#X11UseLocalhost yes
#PrintMotd yes
#PrintLastLog yes
#TCPKeepAlive yes
#UseLogin no
UsePrivilegeSeparation yes
PermitUserEnvironment no
#Compression delayed
ClientAliveInterval 900 
ClientAliveCountMax 0
#ShowPatchLevel no
#UseDNS yes
#PidFile /var/run/sshd.pid
#MaxStartups 10:30:100
#PermitTunnel no
#ChrootDirectory none
Ciphers aes128-ctr,aes192-ctr,aes256-ctr,aes128-cbc,3des-cbc,aes192-cbc,aes256-cbc

# no default banner path
Banner /etc/issue.net

# override default of no subsystems
Subsystem       sftp    /usr/libexec/openssh/sftp-server

# Example of overriding settings on a per-user basis
#Match User anoncvs
#       X11Forwarding no
#       AllowTcpForwarding no
#       ForceCommand cvs server
EOF
systemctl restart sshd

cat << EOF > /etc/pam.d/system-auth
#%PAM-1.0
# This file is auto-generated.
# User changes will be destroyed the next time authconfig is run.
auth        required      pam_env.so
auth        requisite     pam_faillock.so preauth audit deny=5 even_deny_root unlock_time=900
auth        sufficient    pam_fprintd.so
auth        sufficient    pam_unix.so try_first_pass
auth        requisite     pam_succeed_if.so uid >= 500 quiet
auth        [default=die] pam_faillock.so authfail audit deny=5 even_deny_root unlock_time=900 fail_interval=900
auth        required      pam_deny.so

account     required      pam_faillock.so
account     required      pam_unix.so
account     sufficient    pam_localuser.so
account     sufficient    pam_succeed_if.so uid < 500 quiet
account     required      pam_permit.so

password    required      pam_cracklib.so try_first_pass retry=3 minlen=8 dcredit=-1 ucredit=-1 ocredit=-1 lcredit=-1
password    sufficient    pam_unix.so sha512 shadow try_first_pass use_authtok remeber=5
password    required      pam_deny.so

session     optional      pam_keyinit.so revoke
session     required      pam_limits.so
session     required      pam_lastlog.so showfailed
session     [success=1 default=ignore] pam_succeed_if.so service in crond quiet use_uid
session     required      pam_unix.so
EOF

cat << EOF > /etc/pam.d/system-auth
auth        required      pam_env.so
auth        requisite     pam_faillock.so preauth audit deny=5 even_deny_root unlock_time=900
auth        sufficient    pam_unix.so try_first_pass
auth        requisite     pam_succeed_if.so uid >= 500 quiet
auth        [default=die] pam_faillock.so authfail audit deny=5 even_deny_root unlock_time=900 fail_interval=900
auth        required      pam_deny.so

account     required      pam_faillock.so
account     required      pam_unix.so
account     sufficient    pam_localuser.so
account     sufficient    pam_succeed_if.so uid < 500 quiet
account     required      pam_permit.so

password    required      pam_cracklib.so try_first_pass retry=3 minlen=8 dcredit=-1 ucredit=-1 ocredit=-1 lcredit=-1
password    sufficient    pam_unix.so sha512 shadow try_first_pass use_authtok remeber=5
password    required      pam_deny.so

session     optional      pam_keyinit.so revoke
session     required      pam_limits.so
session     required      pam_lastlog.so showfailed
session     [success=1 default=ignore] pam_succeed_if.so service in crond quiet use_uid
session     required      pam_unix.so
EOF

cat << EOF > /etc/pam.d/su
#%PAM-1.0
auth            sufficient      pam_rootok.so
# Uncomment the following line to implicitly trust users in the "wheel" group.
#auth           sufficient      pam_wheel.so trust use_uid
# Uncomment the following line to require a user to be in the "wheel" group.
auth           required        pam_wheel.so use_uid
auth            include         system-auth
account         sufficient      pam_succeed_if.so uid = 0 use_uid quiet
account         include         system-auth
password        include         system-auth
session         include         system-auth
session         optional        pam_xauth.so
EOF

sed -i 's/PASS_MAX_DAYS.*/PASS_MAX_DAYS 90/g' /etc/login.defs
sed -i 's/PASS_MIN_DAYS.*/PASS_MIN_DAYS 7/g' /etc/login.defs
sed -i 's/PASS_MIN_LEN.*/PASS_MIN_LEN 8/g' /etc/login.defs
sed -i 's/PASS_WARN_AGE.*/PASS_WARN_AGE 7/g' /etc/login.defs
sed -i 's/ENCRYPT_METHOD.*/ENCRYPT_METHOD SHA512/g' /etc/login.defs

sed -i 's/umask.*/umask 027/g' /etc/bashrc
sed -i 's/umask.*/umask 027/g' /etc/profile
sed -i 's/umask.*/umask 027/g' /etc/csh.cshrc

cat << EOF > /etc/motd
****************************************************
*             NOTE - PROPRIETARY SYSTEM            *
*  THIS SYSTEM IS INTENDED TO BE USED SOLELY BY    *
*  AUTHORIZED USERS IN THE COURSE OF LEGITIMATE    *
*  CORPORATE BUSINESS. USERS ARE MONITORED TO      *
*  THE EXTENT NECESSARY TO PROPERLY ADMINISTER     *
*  THE SYSTEM, TO IDENTIFY UNAUTHORIZED USERS      *
* OR USERS OPERATING BEYOND THEIR PROPER AUTHORITY *
*  AND TO INVESTIGATE IMPROPER ACCESS OR USE. BY   *
*  ACCESSING THIS SYSTEM, YOU ARE CONSENTING TO    *
*                THIS MONITORING.                  *
****************************************************
EOF

cat << EOF > /etc/issue
****************************************************
*             NOTE - PROPRIETARY SYSTEM            *
*  THIS SYSTEM IS INTENDED TO BE USED SOLELY BY    *
*  AUTHORIZED USERS IN THE COURSE OF LEGITIMATE    *
*  CORPORATE BUSINESS. USERS ARE MONITORED TO      *
*  THE EXTENT NECESSARY TO PROPERLY ADMINISTER     *
*  THE SYSTEM, TO IDENTIFY UNAUTHORIZED USERS      *
* OR USERS OPERATING BEYOND THEIR PROPER AUTHORITY *
*  AND TO INVESTIGATE IMPROPER ACCESS OR USE. BY   *
*  ACCESSING THIS SYSTEM, YOU ARE CONSENTING TO    *
*                THIS MONITORING.                  *
****************************************************
EOF

cat << EOF > /etc/issue.net
****************************************************
*             NOTE - PROPRIETARY SYSTEM            *
*  THIS SYSTEM IS INTENDED TO BE USED SOLELY BY    *
*  AUTHORIZED USERS IN THE COURSE OF LEGITIMATE    *
*  CORPORATE BUSINESS. USERS ARE MONITORED TO      *
*  THE EXTENT NECESSARY TO PROPERLY ADMINISTER     *
*  THE SYSTEM, TO IDENTIFY UNAUTHORIZED USERS      *
* OR USERS OPERATING BEYOND THEIR PROPER AUTHORITY *
*  AND TO INVESTIGATE IMPROPER ACCESS OR USE. BY   *
*  ACCESSING THIS SYSTEM, YOU ARE CONSENTING TO    *
*                THIS MONITORING.                  *
****************************************************
EOF

chown root:root /etc/motd
chmod 644 /etc/motd
chown root:root /etc/issue
chmod 644 /etc/issue
chown root:root /etc/issue.net
chmod 644 /etc/issue.net

chmod 644 /etc/passwd
chown root:root /etc/passwd
chmod 000 /etc/shadow
chown root:root /etc/shadow
chmod 000 /etc/gshadow
chown root:root /etc/gshadow
chmod 644 /etc/group
chown root:root /etc/group