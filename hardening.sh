#!/bin/bash
###########################################################################
##
## $Id: //AV/main/syseng/security/hardening/greenlight/hardening.sh#85 $
##
##
## NOTES: The GEN numbers are a reference to the DOD/STIG finding that they
##        address. For example, GEN000500 refers to a test that the SRR
##        scripts perform to determine if the system is setup to automatically
##        logout terminal (local and remote) sessions that are idle for 15
##        minutes. If the SRR scripts find that there is not timeout set on
##        the system being tested, it is reported as a finding and must be
##        resolved or attributed somehow.
###########################################################################
## Check to make sure this is run by root or exit
[ "`whoami`" = "root" ] || { echo "ERROR: this program must be run as root" ; exit 1; }

## Verify that this is run on SuSE Enterprise Linux or exit
if [ ! -e /etc/SuSE-release ]; then
    if [ -e /etc/os-release ]; then
        IS_SUSE=`egrep -i -w "SLES|SUSE" /etc/os-release | wc -l`
        if [ "$IS_SUSE" -eq "0" ]; then
            echo "ERROR: this program must be run on SuSE Linux"
            exit 1
        fi
    else
        echo "ERROR: this program must be run on SuSE Linux"
        exit 1
    fi
fi

syslog_installed=`rpm -q syslog-ng | grep -v 'not installed'`
snmp_installed=`rpm -q net-snmp | grep -v 'not installed'`

## We are logging all the output of this script for later review
DATE=`date '+%Y-%m-%d %H:%M:%S'`
logfile=/var/log/hardening.log
savefile=/usr/local/avamar/install/hardening.perms.save
[ -d /usr/local/avamar/install ] || mkdir -p /usr/local/avamar/install
savext=avbkup
restoreext=avrestore
touch /var/log/hardening.log
chmod 640 $logfile

# File containing users whose shells were changed. For reading during restore to avoid users targeted in this
# script who were already set to no access prior to hardening being granted access upon restore.
changed_shells=/var/log/changedshells.log
touch $changed_shells
chmod 600 $changed_shells

#Redirect any errors to the log file
exec 2>>$logfile

if [ ! -f $savefile ]; then
    touch $savefile
    chmod 750 $savefile
    oktosave=true
fi

function back_up_file() {
    file="$1"
    if [ -e "$file" ]; then
        if [ ! -e ${file}.$savext ] ; then
            [ -f "${file}" ] && cp -p ${file} ${file}.$savext
        fi
    fi
}

function restore_file() {
    file="$1"
    if [ -e "$file" ]; then
        if [ -e ${file}.$savext ] ; then
        [ -f "$file" ] && cp -p ${file} ${file}.$restoreext
            [ -f "${file}.$savext" ] && cp -p ${file}.$savext ${file}
        fi
    fi
}

function change_file_perms() {
    mode="$1"
    shift
    for i in $*
    do
        file="$i"
        if [ -e "$file" ]; then
            if [ "$oktosave" = true ]; then
                find $file -wholename $file -printf '[ -e %p ] && chmod %#m %p\n' >> $savefile
            fi
            chmod $mode $file
        fi
    done
}
function change_file_owner() {
    owner="$1"
    shift
    for i in $*
    do
        file="$i"
        if [ -e "$file" ]; then
            if [ "$oktosave" = true ]; then
                find $file -wholename $file -printf '[ -e %p ] && chown %u:%g %p\n' >> $savefile
            fi
            chown $owner $file
        fi
    done
}

function change_file_ownership() {
    owner="$1"
    group="$2"
    file="$3"
    if [ -e "$file" ]; then
        if [ "$oktosave" = true ]; then
            find $file -wholename $file -printf '[ -e %p ] && chown %u:%g %p\n' >> $savefile
        fi
        chown $owner:$group $file
    fi
}

function Perl() {
    if [ $# -gt 2 ]; then
        args=$#
        file=${!args}
        if [ -e ${file} ]; then
            echo "$*" | xargs perl
        fi
    fi
}

function append_to_sshdconfig() {
    new_line=$1
    echo "Add '${line}' to ${SSHDCONFIG}" | tee -a $logfile
    if grep -iqP "^Match" ${SSHDCONFIG}; then
        # Match blocks found in sshd_config, insert new line before the first Match block.
        sed -i '0,/^[Mm]atch.*/s/^[Mm]atch.*/'"${new_line}"'\n&/' ${SSHDCONFIG}
    else
        # No Match blocks in sshd_config, append new line to the end of the file.
        echo $new_line >> ${SSHDCONFIG}
    fi
}

function enable_hostkey() {
    key_name=$1
    ssh_host_loc='/etc/ssh/ssh_host_'
    hostkey_to_add=$ssh_host_loc"$key_name"
    hostkey_to_add_regex='\/etc\/ssh\/ssh_host_'$key_name

    if [ -f $hostkey_to_add ]; then # only enable the HostKey if the key files exist. Private key checked in this case.
      hostkey_grep="#\s*HostKey.+$hostkey_to_add"
      if grep -iqP $hostkey_grep ${SSHDCONFIG}; then
        echo "Found HostKey $key_name commented out. Enabling it to remove default HostKeys." | tee -a $logfile
        Perl -pi -e "\"s/#.*(HostKey.+$hostkey_to_add_regex)/\$1/\"" ${SSHDCONFIG}
      elif grep -iqP "HostKey.+$hostkey_to_add" ${SSHDCONFIG}; then
        echo "HostKey $key_name is already being used. No actions need to be taken for HostKey." | tee -a $logfile
      else
        # add the new HostKey lines under the last HostKey specified in the sshd_conf. If none, then will use the last HostKey comment.
        hostkey_grep=`grep -iP "#?\s*hostkey.*" ${SSHDCONFIG} | tail -1`
        echo "Going to add $hostkey_to_add_regex under \"$hostkey_grep\""
        hostkey_grep=`echo ${hostkey_grep//\//\\\/}`
        hostkey_grep=`echo ${hostkey_grep// /\\\s*}`
        Perl -pi -e "\"s/$hostkey_grep/$&\nHostKey $hostkey_to_add_regex/\"" ${SSHDCONFIG}
      fi
    fi
}

function disable_hostkey() {
    key_to_disable=$1
    echo "Disabling $key_to_disable in ${SSHDCONFIG}"
    Perl -pi -e "\"s/^\s*(HostKey.*$key_to_disable)/#\$1/\""  ${SSHDCONFIG}
}

echo "-------------------------- ${DATE} --------------------------" >> $logfile
echo "Avamar Hardening Script ${DATE}"

##      GEN000500 - There is no terminal lockout after 15 inactive minutes
##                  requiring the account password to resume
##    GEN002560 - The system and user default umask is not 077
PROFILE=/etc/profile
if grep -q TMOUT $PROFILE ; then
    echo "Terminal timeout already set in ${PROFILE}..." | tee -a $logfile
    echo "[DONE]" | tee -a $logfile
else
    echo "Adding terminal timeout..." | tee -a $logfile
    # [ -e ${PROFILE}.$savext ] || cp -p ${PROFILE} ${PROFILE}.$savext
    cat << EOF >> ${PROFILE}
# adding console timeout Avamar Hardening script
TMOUT=900
export TMOUT
EOF
    echo "[DONE]" | tee -a $logfile
fi

#Bug 281608 use "secure local" for suseconfig defaut permission level, in case some osrollup rpm may apply the default suseconfig permission.
PERMISSION_CONFIG=/etc/sysconfig/security
if [ -f ${PERMISSION_CONFIG} ]; then
    if egrep -qi "^PERMISSION_SECURITY" ${PERMISSION_CONFIG}; then
        sed -i 's/PERMISSION_SECURITY\=\"easy local\"/PERMISSION_SECURITY\=\"secure local\"/g' ${PERMISSION_CONFIG}
    fi
fi
chkstat -set /etc/permissions.secure

##     GEN000920 - Root Account Home Directory Permissions
echo "Changing /root permissions..." | tee -a $logfile
change_file_perms 700 /root
echo "[DONE]" | tee -a $logfile

##     GEN001260 - System Log File Permissions
echo "Changing log and logrotate permissions..." | tee -a $logfile
Perl -i.$savext -pe "'s/^(\s*create\s+)\d+(.*)/\${1}640\$2/;'" /etc/logrotate.d/apache2
rm -f /etc/logrotate.d/commlog.$savext
rm -f /etc/logrotate.d/apache2.$savext
# defer tightening permissions to 640 in dpnmcs.logrotate - bug #31368
Perl -i.$savext -pe "'s/^(\s*create\s+)\d+(.*)/\${1}660\$2/;'" /etc/logrotate.d/dpnmcs.logrotate
rm -f /etc/logrotate.d/dpnmcs.logrotate.$savext
change_file_perms 770 /usr/local/avamar/var/cron
change_file_perms 640 /var/log/cron*
change_file_perms 640 /var/log/dmesg
change_file_perms 640 /var/log/snmpd*
change_file_perms 640 /var/log/spooler*
change_file_perms 640 /var/log/messages*
change_file_perms 640 /var/log/secure*
change_file_perms 640 /var/log/boot*
change_file_perms 640 /var/log/ssclp.log
change_file_perms 640 /var/log/lsi_*.log
change_file_perms 640 /var/log/maillog*
change_file_perms 640 /var/log/ntp
change_file_perms 640 /var/log/scpm
change_file_perms 640 /var/log/warn
change_file_perms 640 /var/log/wtmp
change_file_perms 640 /var/log/mail*
change_file_perms 640 /var/log/lastlog
change_file_perms 640 /var/log/firewall
change_file_perms 640 /var/log/YaST2/*
echo "[DONE]" | tee -a $logfile

#echo "Moving backup files for safekeeping..." | tee -a $logfile
#[ -d /etc/logrotate.d.$savext ] || mkdir /etc/logrotate.d.$savext
#function move_logrotate_backup() {
#    src_file="$1"
#
#    src_dir=/etc/logrotate.d
#    dst_dir=/etc/logrotate.d.$savext
#
#    if [ ! -e "${dst_dir}/${src_file}.$savext" ] ; then
#        mv "${src_dir}/${src_file}.$savext" "${dst_dir}/${src_file}.$savext"
#    else
    # bug #52999 - logrotate complains about duplicate entries if backup files are created in /etc/logrotate.d directory...
    # keep only the first original copy
#        rm -f ${src_dir}/$src_file
#   fi
#}

#move_logrotate_backup apache2
#move_logrotate_backup commlog
#move_logrotate_backup dpnmcs.logrotate

console_kit_installed=`rpm -q ConsoleKit | grep -v 'not installed'`
if [[ -n "$console_kit_installed" ]]; then
    change_file_perms 640 /var/log/ConsoleKit/history
fi

change_file_perms 640 /var/log/messages
change_file_ownership root admin /var/log/messages

if [[ -n "$syslog_installed" ]]; then
    back_up_file /etc/syslog-ng/syslog-ng.conf
    sed -e 's|/var/log/messages"|/var/log/messages" group(admin)|' /etc/syslog-ng/syslog-ng.conf > /tmp/tmpfile$$
    cp /tmp/tmpfile$$ /etc/syslog-ng/syslog-ng.conf
    rm /tmp/tmpfile$$
    echo "[DONE]" | tee -a $logfile
fi

#   GEN001280 - Manual Page Permissions
echo "Changing manual file page permissions..." | tee -a $logfile
find /usr/share/man -type f -exec chmod 644 {} \;
echo "[DONE]" | tee -a $logfile

##     GEN001420 - Shadow File Permissions
echo "Changing the permissions on /etc/shadow..." | tee -a $logfile
change_file_perms 400 /etc/shadow
echo "[DONE]" | tee -a $logfile

##     GEN003080/GEN003180 - Crontab and Cronlog File Permissions
echo "Changing the permissions of cron files..." | tee -a $logfile
change_file_perms 600 /etc/cron.d/novell.com-suse_register
change_file_perms 600 /etc/cron.d/ntpd_keepalive
change_file_perms 700 /etc/cron.daily/*
change_file_perms 700 /etc/cron.weekly/*
change_file_perms 700 /etc/cron.hourly/*
change_file_perms 700 /etc/cron.monthly/*
change_file_perms 600 /etc/cron.weekly/aide
change_file_perms 600 /etc/crontab
echo "[DONE]" | tee -a $logfile

##     GEN003520 - Core Dump Permissions
echo "Changing permissions on /var/crash..." | tee -a $logfile
change_file_perms 700 /var/crash
echo "[DONE]" | tee -a $logfile

##     GEN004000 - Traceroute File PermissionsConsole Is World Readable
echo "Changing permissions on traceroute..." | tee -a $logfile
change_file_perms 700 /usr/sbin/traceroute
change_file_perms 700 /usr/sbin/traceroute6
echo "[DONE]" | tee -a $logfile

if [[ -n "$syslog_installed" ]]; then
    ##     GEN005400 - Syslog.conf Permissions
    echo "Changing permissions on /etc/syslog.conf..." | tee -a $logfile
    change_file_perms 600 /etc/syslog.conf
    echo "[DONE]" | tee -a $logfile
fi

#33.     LNX00520 - Sysctl.conf Vulnerabilities
echo "Changing permissions on /etc/sysctl.conf..." | tee -a $logfile
change_file_perms 600 /etc/sysctl.conf
echo "[DONE]" | tee -a $logfile

##    /etc and /var/log file permissions
echo "Changing permissions on log files..." | tee -a $logfile
if [ -h /var/log/mysqld.log ]; then
    rm -f /var/log/mysqld.log
fi
filelist=`find /var/log /etc -name '*.log' -print`
for f in $filelist
do
    change_file_perms 600 $f
done
echo "[DONE]" | tee -a $logfile

#?     GEN003740 - inetd.conf file permissions more than 440 & xinetd.d directory is more than 755
echo "Changing permissions on /etc/xinetd.conf..." | tee -a $logfile
change_file_perms 440 /etc/xinetd.conf
change_file_perms 755 /etc/xinetd.d
echo "[DONE]" | tee -a $logfile

#?    GEN001480 - User home directories have permissions greater than 750
echo "Securing home directory permissions..." | tee -a $logfile
change_file_perms 750 /home/admin
change_file_perms 750 /home/dpn
change_file_perms 750 /home/gsan
echo "[DONE]" | tee -a $logfile

#?    GEN001580 - System startup files are more permissive than 755
echo "Changing permissions on /etc/init.d/rc.local..." | tee -a $logfile
change_file_perms 755 /etc/init.d/rc.local
echo "[DONE]" | tee -a $logfile

#?    GEN001880 - local initialization files are more permissive than 740
# Taking care of all dot '.' files as well as .out and .tgz files listed in the bug
echo "Changing permissions on local initialization files..." | tee -a $logfile
change_file_perms 740 /home/dpn/.avamar
change_file_perms 740 /home/dpn/.bash_logout
change_file_perms 740 /home/dpn/.bash_profile
change_file_perms 740 /home/dpn/.bashrc
change_file_perms 740 /home/dpn/.emacs
change_file_perms 740 /home/dpn/.inputrc
change_file_perms 740 /home/dpn/.gnu-emacs
change_file_perms 740 /home/dpn/.profile
change_file_perms 740 /home/dpn/.vimrc
change_file_perms 740 /home/dpn/.gtkrc
change_file_perms 740 /home/gsan/.bashrc
change_file_perms 740 /home/gsan/.emacs
change_file_perms 740 /home/gsan/.gnu-emacs
change_file_perms 740 /home/gsan/.inputrc
change_file_perms 740 /home/gsan/.profile
change_file_perms 740 /home/gsan/.vimrc
change_file_perms 740 /home/admin/.emacs
change_file_perms 740 /home/admin/.inputrc
change_file_perms 740 /home/admin/.gnu-emacs
change_file_perms 740 /home/admin/.profile
change_file_perms 740 /home/admin/.vimrc
change_file_perms 740 /home/admin/.avamar
for i in /home/{admin,dpn}/.??* /home/{admin,dpn}/0.*/*.{out,tgz}
do
    if [ -f $i ]; then
        change_file_perms 740 $i
    fi
done
echo "[DONE]" | tee -a $logfile

#?    GEN002480 - There are world writeable files or world writeable directories that are not public directories
change_file_perms 500 /usr/local/avamar/bin/dset_script

#?    LNX00440 - The /etc/security/access.conf file is more permissive than 640
echo "Changing permissions on /etc/security/access.conf..." | tee -a $logfile
change_file_perms 640 /etc/security/access.conf
echo "[DONE]" | tee -a $logfile

#?    LNX00660 - The /etc/securetty file is more permissive than 640
echo "Changing permissions on /etc/securetty..." | tee -a $logfile
change_file_perms 640 /etc/securetty
echo "[DONE]" | tee -a $logfile

if [[ -n "$snmp_installed" ]]; then
    #    GEN005320 - The snmpd.conf file is more permissive than 700
    echo "Changing permissions on /etc/snmp/snmpd.conf..." | tee -a $logfile
    change_file_perms 700 /etc/snmp/snmpd.conf
    echo "[DONE]" | tee -a $logfile

    #?    GEN005360 - The snmpd.conf file is not owned by root and group owned by sys or the application
    echo "Changing ownership on /etc/snmp/snmpd.conf..." | tee -a $logfile
    change_file_owner root:sys /etc/snmp/snmpd.conf
    echo "[DONE]" | tee -a $logfile
fi

#11.     GEN000980 - Root Account Access
SECURETTY=/etc/securetty
echo "Creating and adding definition to ${SECURETTY}..." | tee -a $logfile
back_up_file "${SECURETTY}"
cat << EOF >${SECURETTY}
console
tty1
EOF
echo "[DONE]" | tee -a $logfile

#20.     GEN003320 & GEN003280 - Default Accounts/At Utility Accessibility
ATDENY=/etc/at.deny
ATALLOW=/etc/at.allow
echo "Creating and populating ${ATDENY} and ${ATALLOW} for at access control..." | tee -a $logfile
if [ ! -e ${ATDENY} ]; then
    touch ${ATDENY}
    back_up_file ${ATDENY}
else
    back_up_file ${ATDENY}
fi
for user in adm bin daemon ftp gdm haldaemon lp mail man messagebus mysql named news nobody ntp smmsp sshd uucp wwwrun ; do
    if ! grep -q $user $ATDENY ; then
        echo "${user}" >>$ATDENY
    fi
done

# Creating at.deny file for access control
echo "Populating /etc/at.allow and /etc/at.deny for at access control..." | tee -a $logfile
if [ ! -e ${ATALLOW} ]; then
    touch ${ATALLOW}
    back_up_file ${ATALLOW}
else
    back_up_file ${ATALLOW}
fi
for user in root admin
do
    if egrep -q '^${user}' ${ATALLOW} ; then
        continue
    else
        echo $user >> ${ATALLOW}
    fi
done
echo "[DONE]" | tee -a $logfile

# SLES12 STIG, CAT I, ID: SLES-12-010610, Vuln ID: V-77171
# Rule Title: The SUSE operating system must disable the x86 Ctrl-Alt-Delete key sequence.
echo "Disabling Ctrl-Alt-Delete key sequence..." | tee -a $logfile
systemctl mask ctrl-alt-del.target
systemctl daemon-reload
echo "[DONE]" | tee -a $logfile

#2.2.8 Disable SSH protocol version1 and use version 2 only.
SSHDCONFIG=/etc/ssh/sshd_config
echo "Disabling ssh v1 and checking ${SSHDCONFIG}..." | tee -a $logfile
back_up_file ${SSHDCONFIG}
egrep -qi '^\s*Protocol\s*2\s*$'         ${SSHDCONFIG} || append_to_sshdconfig 'Protocol 2'
egrep -qi '^\s*LogLevel\s*INFO\s*$'      ${SSHDCONFIG} || append_to_sshdconfig 'LogLevel INFO'
egrep -qi '^\s*DenyUsers\s*postgres\s*$' ${SSHDCONFIG} || append_to_sshdconfig 'DenyUsers postgres'

# SLES12 STIG, CAT I, ID: SLES-12-030150, Vuln ID: V-77451
# Rule Title: The SUSE operating system must not allow unattended or automatic logon via SSH.
sed -i 's/^PermitEmptyPasswords.*/PermitEmptyPasswords no/g' ${SSHDCONFIG}
sed -i 's/^PermitUserEnvironment.*/PermitUserEnvironment no/g' ${SSHDCONFIG}
egrep -qi '^\s*PermitEmptyPasswords\s*no\s*$'  ${SSHDCONFIG} || append_to_sshdconfig "PermitEmptyPasswords no"
egrep -qi '^\s*PermitUserEnvironment\s*no\s*$' ${SSHDCONFIG} || append_to_sshdconfig "PermitUserEnvironment no"

# SLES12 STIG, CAT I, ID: SLES-12-030260, Vuln ID: V-77473
# Rule Title: The SUSE operating system SSH daemon must encrypt forwarded remote X connections for interactive users.
sed -i 's/^X11Forwarding.*/X11Forwarding yes/g' ${SSHDCONFIG}
egrep -qi '^\s*X11Forwarding\s*yes\s*$' ${SSHDCONFIG} || append_to_sshdconfig "X11Forwarding yes"

# STIG, CAT I,  Vuln ID:V-55159
# Rule Title: The network device must terminate all network connections associated with a device management session at the end of the session,
# or the session must be terminated after 10 minutes of inactivity except to fulfill documented and validated mission requirements.
# Bug 327790: we need to set ClientAliveCountMax to 1 so that when running a very long operation via SSH such as "dpnctl stop", the SSH session won't
# be terminated. Also this is a requirement for the SUSE STIG V-81801(SLES-12-030191).
sed -i 's/^ClientAliveInterval.*/ClientAliveInterval 600/g' ${SSHDCONFIG}
sed -i 's/^ClientAliveCountMax.*/ClientAliveCountMax 1/g' ${SSHDCONFIG}

egrep -qi '^\s*ClientAliveInterval\s*600\s*$' ${SSHDCONFIG} || append_to_sshdconfig "ClientAliveInterval 600"
egrep -qi '^\s*ClientAliveCountMax\s*1\s*$' ${SSHDCONFIG} || append_to_sshdconfig "ClientAliveCountMax 1"

# STIG, CAT I,  Vuln ID:V-72989
# Rule Title: PostgreSQL must implement NIST FIPS 140-2 validated cryptographic modules to generate and validate cryptographic hashes.
# Note: Just use V-72989 for track propose. The reqirment to disable the postgres login is actually not in V-72989
sed -i 's/\(^postgres.*\)bin\/bash/\1sbin\/nologin/g' /etc/passwd

# STIG, rule Vul ID: V-77105
# Rule Title: The SUSE operating system must configure the Linux Pluggable Authentication Modules (PAM) to only store encrypted representations of passwords.
# Note: here we need to check if the symbolic link is not broken
COMMON_PASSWORD_CONF=/etc/pam.d/common-password
if [ -L "$COMMON_PASSWORD_CONF" ]; then
    # the symbolic link is not broken by the stig hardening, we should modify "common-password-pc" rather than the
    # symbolic, so that it won't be broken
    COMMON_PASSWORD_CONF=/etc/pam.d/common-password-pc
fi
grep sha512 $COMMON_PASSWORD_CONF
if [ $? -eq 1 ]; then
    sed -i 's/pam_unix.so/pam_unix.so sha512/g' $COMMON_PASSWORD_CONF
fi

# STIG rules:
# STIG ID: SRG-APP-000166-NDM-000254; Rule Title: The network device must enforce password complexity by requiring that at least one upper-case character be used.
# STIG ID: SRG-APP-000167-NDM-000255; Rule Title: The network device must enforce password complexity by requiring that at least one lower-case character be used.
# STIG ID: SRG-APP-000168-NDM-000256; Rule Title: The network device must enforce password complexity by requiring that at least one numeric character be used.
# STIG ID: SRG-APP-000169-NDM-000257; Rule Title: The network device must enforce password complexity by requiring that at least one special character be used.
CREDIT_FLAGS="lcredit=-1 ucredit=-1 dcredit=-1 ocredit=-1 enforce_for_root"
LINE="password        requisite       pam_cracklib.so       $CREDIT_FLAGS"
# Note: here we just replace the rules of the complexity of the password and keep other rules
sed -i "s/^password.*pam_cracklib.so.*/$LINE/" $COMMON_PASSWORD_CONF

# Also we need to update the password policy warning banne
WARN=/etc/passwd_warn
cat<< EOF > ${WARN}
********** WARNING **********
Password complexity minimum requirements
- at least 1 upper case characters
- at least 1 lower case characters
- at least 1 numerical characters
- at least 1 special characters (i.e. !@#.,)
EOF

# STIG, CAT I,  Vuln ID:V-92751
# Rule Title: The account used to run the Apache web server must not have a valid login shell and password defined.
grep 'User=wwwrun' /usr/lib/systemd/system/apache2.service >/dev/null 2>&1
if [ $? -eq 0 ]; then
    change_file_owner wwwrun:www /usr/sbin/suexec
    change_file_perms 700 /usr/sbin/suexec
fi

# 297564 : The kex and MACs can't added into sshd_config if the SSH version is too old
openssh_version=`rpm -qa |grep openssh |grep -o openssl1-[1-9][0-9]*\.[1-9][0-9]* |awk -F '-' '{print $2;}'`
if [ -z "$openssh_version" ];then
    openssh_version=`rpm -q openssh | grep -o [1-9][0-9]*\.[1-9][0-9]* |head -n 1`
fi

# Hardening the algrithms for ssh.
# Since 19.3, for all nodes except accerator, more hardending needed to match fips requirments
SSHCONFIG=/etc/ssh/ssh_config
node_cfg_fn='/usr/local/avamar/etc/node.cfg'
accerator=false
egrep -qi "accelerator" ${node_cfg_fn}
if [ $? -eq 0 ]; then
    accerator=true
fi

if [ `expr $openssh_version \>\= 6.5` -eq 1 ];then
    if [ $accerator == true ]; then
        kex_algorithms='kexalgorithms diffie-hellman-group-exchange-sha256,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,curve25519-sha256\@libssh.org'
    else
        fips_on=0
        if [ -f "/proc/sys/crypto/fips_enabled" ];then
            fips_on=`cat /proc/sys/crypto/fips_enabled`
        fi
        if [ $fips_on -eq 1 ]; then
            # 19.3, hardening for fips
            kex_algorithms='kexalgorithms ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521'
        else
            kex_algorithms='kexalgorithms ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256'
        fi
    fi

    if egrep -qi "^kexalgorithms" ${SSHDCONFIG} ; then
       if egrep -qi "^$kex_algorithms$" ${SSHDCONFIG} ; then
           echo "No need to harden key exchange algorithms in ${SSHDCONFIG}" | tee -a $logfile
       else
           echo "Hardening SSH key exchange algorithms in ${SSHDCONFIG}" | tee -a $logfile
           Perl -0 -pi -e "\"s/\nkexalgorithms.*/\n$kex_algorithms/i\"" ${SSHDCONFIG}
       fi
    else
        kex_algorithms_str=`echo ${kex_algorithms} | sed 's/\\\//g'`
        append_to_sshdconfig "${kex_algorithms_str}"
    fi
else
    echo "Can't harden key exchange algorithms in ${SSHDCONFIG} as the SSH version is too old" | tee -a $logfile
fi

# Specify cipher list to be used. Overwrites pre-existing list if it doesn't match the expected $cipher_algos below.
guaranteed_line='LogLevel INFO'
    if [ $accerator == true ]; then
        cipher_algos='Ciphers aes128-ctr,aes192-ctr,aes256-ctr'
    else
        # 19.3, hardening for fips
        cipher_algos='Ciphers aes128-ctr,aes192-ctr,aes256-ctr,aes128-cbc,aes192-cbc,aes256-cbc'
        if egrep -qi "^$cipher_algos$" ${SSHCONFIG} ; then
            echo "No need to harden SSH ciphers in ${SSHCONFIG}" | tee -a $logfile
        else
            echo "Hardening SSH ciphers in ${SSHCONFIG}" | tee -a $logfile
            sed -i "/^Ciphers/d" ${SSHCONFIG}
            echo ${cipher_algos} >> ${SSHCONFIG}
        fi
    fi

if egrep -qi "^$cipher_algos$" ${SSHDCONFIG} ; then
        echo "No need to harden SSH ciphers in ${SSHDCONFIG}" | tee -a $logfile
else
        echo "Hardening SSH ciphers in ${SSHDCONFIG}" | tee -a $logfile
        Perl -0 -pi -e "\"s/(\n$guaranteed_line)(\nCiphers.*)?/\1\n$cipher_algos/i\"" ${SSHDCONFIG}
fi



# Check if MAC algorithms are defined and add directly under the cipher list. If upgrading, previous MAC line will be overwritten
#mac_algos='MACs hmac-sha2-512-etm\@openssh.com,hmac-sha2-512,hmac-sha2-256-etm\@openssh.com,hmac-sha2-256,umac-128-etm\@openssh.com,umac-128\@openssh.com'
mac_algos='MACs hmac-sha2-512-etm\@openssh.com,hmac-sha2-512,hmac-sha2-256-etm\@openssh.com,hmac-sha2-256'
if [ $accerator == true ]; then
    echo "SSH version in accelerator node does not support ${mac_algos} MAC config, Ignoring..." | tee -a $logfile
else
    if egrep -qi "^$mac_algos$" ${SSHDCONFIG} ; then
         echo "No need to harden MAC algorithms in ${SSHDCONFIG}" | tee -a $logfile
    elif [ `expr $openssh_version \>\= 6.5` -eq 1 ];then
        echo "Hardening MAC algorithms in ${SSHDCONFIG}" | tee -a $logfile
        Perl -0 -pi -e "\"s/(\nCiphers\s(\w+-?\w+,?)+)(\nMACs.*)?/\$1\n$mac_algos/i\"" ${SSHDCONFIG} # Perl handles multiline sub well
    else
        echo "Can't harden MAC algorithms in ${SSHDCONFIG} as SSH version is too old" | tee -a $logfile
    fi
fi
# Ensure default Hostkeys are not enabled by setting them ourselves
enable_hostkey rsa_key
enable_hostkey ecdsa_key
disable_hostkey ed25519_key

echo "check whether sshd config is healthy before restart sshd" | tee -a $logfile
/usr/sbin/sshd -t
if [ $? -eq 0 ] ; then
    echo "Health check ${SSHDCONFIG} passed"  | tee -a $logfile
    service sshd restart
else
    echo "Health check ${SSHDCONFIG} failed and restore the backup config" | tee -a $logfile
    restore_file ${SSHDCONFIG}
fi

echo "[DONE]" | tee -a $logfile

#2.2.11.Unnecessary service is running: xinetd is enabled.  It is not
#clear in the hardening document if it was required. If it is not
#required it should be disabled.
echo "Stopping and disabling xinetd..." | tee -a $logfile
service xinetd stop
chkconfig xinetd off
echo "[DONE]" | tee -a $logfile

#2.3.2.The following accounts are seen in our scan and need to be removed if not needed:
echo "Disabling shell access for accounts..." | tee -a $logfile
back_up_file /etc/shadow
for user in sshd ftp games gdm lp news uucp pulse man at bin daemon nobody suse-ncc dpn; do
    if grep -q "^${user}:" /etc/passwd; then
        output=`chsh -s /sbin/nologin $user`
        if [[ "$output" =~ "Shell changed." ]] ; then
            echo "Access for ${user} disabled."
            echo $user >> $changed_shells
        fi
    fi
done
passwd -l ssh

if grep -q "^dpn:" /etc/passwd; then
    echo "disabling dpn user password authentication" | tee -a $logfile
    passwd -l dpn
fi

echo "Removing unused groups..." | tee -a $logfile
back_up_file /etc/group
for group in audio cdrom dialout ntadmin ftp games gdm lp; do
    if grep -q "^${group}:" /etc/group; then
        # Delete associated users before delete group.
        for user in `cut -d: -f1,4 /etc/passwd | grep ":$(getent group ${group} | cut -d: -f3)$" | cut -d: -f1`; do
            echo "Delete associated user[${user}] before delete group[${group}] ." | tee -a $logfile
            userdel ${user}
        done
        groupdel $group
    fi
done
echo "[DONE]" | tee -a $logfile

echo "Ban user sshd password login..." | tee -a $logfile
# 'sshd' user has no password configured. Ban password login to prevent potential vulnerability exploit.
sed -i "s#^sshd::#sshd:\*:#g" /etc/shadow
echo "[DONE]" | tee -a $logfile

if [[ -n "$snmp_installed" ]]; then
    #2.2.5.SNMP is used on the AVAMAR device. We are detecting a public
    #community name.  Modify community string and use version 3.
    #NOTE:  Still need to work with Dell Support in implementing v3 for openmanage.
    # User can specify the new community name.
    echo "Modifying snmpd community name..." | tee -a $logfile
    COMMNAME=private
    back_up_file /etc/snmp/snmpd.conf
    Perl -i -pe "\"s/(^com2sec\s+notConfigUser\s+default\s+)public/\$1$COMMNAME/;\"" /etc/snmp/snmpd.conf
    service snmpd restart
    echo "[DONE]" | tee -a $logfile
fi

## Removing unnecessary directories and files for the Tomcat server
echo "Removing unnecessary tomcat directories..." | tee -a $logfile
rm -rf /usr/local/jakarta-tomcat-5.5.9/webapps/{balancer,jsp-examples,ROOT,servlets-examples,tomcat-docs,webdav}
echo "[DONE]" | tee -a $logfile

# per escalation #1211
echo "Removing decode entry from /etc/aliases..." | tee -a $logfile
back_up_file /etc/aliases
Perl -i -pe "\"s/(^decode\:.*root.*$)/\#\$1/;\"" /etc/aliases
echo "[DONE]" | tee -a $logfile

#?    GEN001220 - System files, programs, and directories are not owned by a system account
echo "Setting permissions on system files not group owned by system account..." | tee -a $logfile
change_file_owner root:root /etc/rc.modules
change_file_owner root:root /etc/init.d/zzdpn.*
echo "[DONE]" | tee -a $logfile

#?    LNX00480 - The /etc/sysctl.conf file is not owned by root
echo "Changing ownership of /etc/sysctl.conf..." | tee -a $logfile
change_file_owner root:root /etc/sysctl.conf
echo "[DONE]" | tee -a $logfile

#?    GEN002560 - The system and user default umask is not 077
LOGIN=/etc/login.defs
echo "Modifying login umask to ${LOGIN}..." | tee -a $logfile
if grep -q "umask" $LOGIN ; then
    back_up_file "${LOGIN}"
    #umask    022 to umask 077
    Perl -i -pe "'s/^(UMASK\s+).*/\${1}077/;'" ${LOGIN}
else
    back_up_file "${LOGIN}"
    echo "umask 077" >> $LOGIN
fi

ADMINPROFILE=/home/admin/.bash_profile
echo "Modifying admin umask to ${ADMINPROFILE}..." | tee -a $logfile
if grep -q "umask" $ADMINPROFILE ; then
    back_up_file "${ADMINPROFILE}"
    #umask    022 to umask 077
    Perl -i -pe "'s/^(umask\s+).*/\${1}077/;'" $ADMINPROFILE
else
    back_up_file "${ADMINPROFILE}"
    echo "umask 077" >> $ADMINPROFILE
fi
change_file_owner admin:admin $ADMINPROFILE

ADMINBASHRC=/home/admin/.bashrc
echo "Modifying admin umask to ${ADMINBASHRC}..." | tee -a $logfile
if grep -q "umask" $ADMINBASHRC ; then
    back_up_file "${ADMINBASHRC}"
    #umask    022 to umask 077
    Perl -i -pe "'s/^(umask\s+).*/\${1}077/;'" $ADMINBASHRC
else
    back_up_file "${ADMINBASHRC}"
    echo "umask 077" >> $ADMINBASHRC
fi
change_file_owner admin:admin $ADMINBASHRC

DPNPROFILE=/home/dpn/.bash_profile
echo "Modifying dpn umask to ${DPNPROFILE}..." | tee -a $logfile
if grep -q "umask" $DPNPROFILE ; then
    back_up_file "${DPNPROFILE}"
    #umask    022 to umask 077
    Perl -i -pe "'s/^(umask\s+).*/\${1}077/;'" $DPNPROFILE
else
    back_up_file "${DPNPROFILE}"
    echo "umask 077" >> $DPNPROFILE
fi

DPNBASHRC=/home/dpn/.bashrc
echo "Modifying dpn umask to ${DPNBASHRC}..." | tee -a $logfile
if grep -q "umask" $DPNBASHRC ; then
    back_up_file "${DPNBASHRC}"
    #umask    022 to umask 077
    Perl -i -pe "'s/^(umask\s+).*/\${1}077/;'" $DPNBASHRC
else
    back_up_file "${DPNBASHRC}"
    echo "umask 077" >> $DPNBASHRC
fi

ETCPROFILE=/etc/profile
echo "Modifying umask to ${ETCPROFILE}..." | tee -a $logfile
if grep -q "umask" $ETCPROFILE ; then
    back_up_file "${ETCPROFILE}"
    #umask 022 to umask 077
    Perl -i -npe "'s/^(umask\s+).*/\${1}077/;'" $ETCPROFILE
else
    back_up_file "${ETCPROFILE}"
    echo "umask 077" >> $ETCPROFILE
fi
echo "[DONE]" | tee -a $logfile

#?    GEN006620 - The access control program is not configured to grant and deny system access to specific hosts.
#HOSTSDENY=/etc/hosts.deny
#echo "adding ALL:ALL to ${HOSTSDENY}..."
#back_up_file "${HOSTSDENY}"
#if egrep -q "^ALL:ALL" "${HOSTSDENY}" ; then
#  echo "no change required"
#else
#  echo "ALL:ALL" >> "${HOSTSDENY}"
#fi
#echo "[DONE]"

## have to add sshd access to hosts.allow for remote access
HOSTSALLOW=/etc/hosts.allow
echo "Adding 'sshd : ALL : ALLOW' to ${HOSTSALLOW}..." | tee -a $logfile
back_up_file "${HOSTSALLOW}"
if egrep -q "^sshd " "${HOSTSALLOW}" ; then
  echo "replace existing entry for sshd" | tee -a $logfile
  Perl -i -npe "'s/^sshd .*/sshd : ALL : ALLOW/'" ${HOSTSALLOW}
else
  echo "add entry for sshd" | tee -a $logfile
  echo 'sshd : ALL : ALLOW' >> ${HOSTSALLOW}
fi
echo "[DONE]" | tee -a $logfile

#? GEN002020 - .rhosts, .shosts, or host.equiv files contain other than host-user pairs.
#? GEN002040 - .rhosts, .shosts, hosts.equiv, or shosts.equiv are used and not justified & documented with the IAO.
echo "Removing /etc/hosts.equiv..." | tee -a $logfile
rm -f /etc/hosts.equiv
echo "[DONE]" | tee -a $logfile

#2.2.14.GEN003600. No kernel changes under sysctl.conf
#?    GEN005600 - IP forwarding is not disabled in sysctl.conf
#?    LNX00520  - The /etc/sysctl.conf file is more permissive than 600
# Need to write changes to /etc/sysctl.conf to pass GEN003600 requirement
SYSCTL=/etc/sysctl.conf
echo "Creating and adding definition to ${SYSCTL}..." | tee -a $logfile
back_up_file "${SYSCTL}"
function update_sysctl() {
  parameter="$1"
  value="$2"

  if egrep -q "^${parameter}" /etc/sysctl.conf ; then
    Perl -i -pe "\"s/^${parameter}\\s+.*/${parameter} = ${value}/\"" /etc/sysctl.conf
  else
    echo "${parameter} = ${value}" >> /etc/sysctl.conf
  fi
}

update_sysctl net.ipv4.ip_forward 0
update_sysctl net.ipv4.tcp_max_syn_backlog 1280
update_sysctl net.ipv4.icmp_echo_ignore_broadcasts 1
update_sysctl net.ipv4.icmp_ignore_bogus_error_responses 1
update_sysctl net.ipv4.conf.default.send_redirects 0
update_sysctl net.ipv4.conf.all.send_redirects 0
update_sysctl net.ipv4.icmp_echo_ignore_broadcasts 1
update_sysctl net.ipv4.conf.default.secure_redirects 0
update_sysctl net.ipv4.conf.default.accept_redirects 0
update_sysctl net.ipv4.conf.all.secure_redirects 0
update_sysctl net.ipv4.conf.all.accept_redirects 0
update_sysctl net.ipv4.conf.all.accept_source_route 0
update_sysctl net.ipv4.conf.default.accept_source_route 0
update_sysctl net.ipv4.conf.all.rp_filter 1
update_sysctl net.ipv4.tcp_syncookies 1
update_sysctl net.ipv4.tcp_max_syn_backlog 4096
if [ -n "`lsmod | grep ipv6`" ]; then
  update_sysctl net.ipv6.conf.all.accept_redirects 0
  update_sysctl net.ipv6.conf.default.accept_redirects 0
  update_sysctl net.ipv6.conf.all.accept_source_route 0
  update_sysctl net.ipv6.conf.default.accept_source_route 0
fi
echo "Resetting sysctl..." | tee -a $logfile
sysctl -e -p /etc/sysctl.conf
echo "changing permissions of /etc/sysctl.conf..." | tee -a $logfile
change_file_perms 600 /etc/sysctl.conf
echo "[DONE]" | tee -a $logfile

#     GEN001160 - there are unowned files
echo "Removing unowned files and folders..." | tee -a $logfile
rm -rf /var/lib/news/
rm -rf /etc/news/
rm -rf /var/lib/pulseaudio/
rm -rf /var/lib/gdm/.bash_history
rm -rf /var/lib/pulseaudio/.bash_history
rm -rf /var/lib/pgsql/.bash_profile
rm -rf /var/log/news/news.crit
rm -rf /var/log/news/news.err
rm -rf /var/log/news/news.notice
rm -rf /var/lib/gdm/.profile
rm -rf /var/lib/gdm/.bashrc
rm -rf /var/lib/gdm/.emacs
rm -rf /var/lib/gdm/.gnu-emacs
# Bug 41575
change_file_owner polkituser:ntp /var/lib/PolicyKit
change_file_owner root:root /var/lib/gdm
change_file_owner polkituser:ntp /var/lib/PolicyKit-public
change_file_owner polkituser:ntp /var/lib/PolicyKit.reload
change_file_owner polkituser:ntp /var/lib/misc/PolicyKit.reload
change_file_owner polkituser:ntp /var/run/PolicyKit
# bug 31743
#rm -rf /var/www/manual
#rm -rf /usr/share/apache2/manual
# bug 313704
zypper remove apache2-doc -y

echo "[DONE]" | tee -a $logfile

#     GEN005340 - MIB files more permissive than 640
echo "Changing permissions on vulnerable MIB files" | tee -a $logfile
if [ -d /opt/dell/srvadmin/etc ] ; then
    change_file_perms 640 /opt/dell/srvadmin/etc/srvadmin-storage/dcstorag.mib
    change_file_perms 640 /opt/dell/srvadmin/etc/srvadmin-isvc/mib/10892.mib
    change_file_perms 640 /opt/dell/srvadmin/etc/srvadmin-idrac/dcs3rmt.mib
    change_file_perms 640 /opt/dell/srvadmin/etc/srvadmin-isvc/mib/dcs3fru.mib
    change_file_owner root:sys /etc/snmp/snmpd.conf
    change_file_owner root:sys /opt/dell/srvadmin/sm/mibs/dcstorag.mib
    change_file_owner root:sys /opt/dell/srvadmin/omsa/mibs/10892.mib
    change_file_owner root:sys /opt/dell/srvadmin/omsa/mibs/dcs3fru.mib
    change_file_owner root:sys /opt/dell/srvadmin/idrac/mibs/dcs3rmt.mib
fi
echo "[DONE]" | tee -a $logfile

#     GEN001220 - system files not owned by system account
#     LNX00480 - The /etc/sysctl.conf file is not owned by root
echo "Changing ownership of /etc/sysctl.conf files..." | tee -a $logfile
change_file_owner root:root /etc/sysctl.conf
[ -e "{$SYSCTL}.$savext" ] && chown root:root "${SYSCTL}.$savext"
echo "[DONE]" | tee -a $logfile

#     GEN001560 - user directories have file with permissions over 750
echo "Changing permissions on vulnerable directories..." | tee -a $logfile
change_file_perms 750 /var/lib/empty
change_file_perms 750 /var/cache/man
change_file_perms 750 /var/run/PolicyKit
change_file_perms 750 /var/run/uuidd
change_file_perms 750 /var/lib/wwwrun
change_file_perms 750 /var/lib/YaST2/suse-ncc-fakehome
change_file_perms 750 /var/lib/YaST2/suse-ncc-fakehome/.vimrc
change_file_perms 750 /var/lib/YaST2/suse-ncc-fakehome/.fonts
change_file_perms 750 /var/lib/YaST2/suse-ncc-fakehome/.mozilla
echo "[DONE]" | tee -a $logfile

# Bug 41598
echo "Changing permissions on non-startup files with permissions set too high..." | tee -a $logfile
change_file_perms 750 /home/admin/.avamardata/var
change_file_perms 750 /home/admin/.avamardata/var/mc
change_file_perms 750 /home/admin/.avamardata/var/mc/cli_log
change_file_perms 750 /home/admin/.avamardata/var/mc/cli_log/mccli.log.*
change_file_perms 750 /home/admin/.avamardata/var/mc/cli_data
change_file_perms 750 /var/cache/man/sv
change_file_perms 750 /var/cache/man/sv/cat1
change_file_perms 750 /var/cache/man/sv/catn
change_file_perms 750 /var/cache/man/sv/cat3
change_file_perms 750 /var/cache/man/sv/cat5
change_file_perms 750 /var/cache/man/sv/cat0
change_file_perms 750 /var/cache/man/sv/cat6
change_file_perms 750 /var/cache/man/sv/cat4
echo "[DONE]" | tee -a $logfile

if [[ -n "$syslog_installed" ]]; then
    #     GEN003160 - cron logging not implemented
    SYSLOGNG=/etc/syslog-ng/syslog-ng.conf
    echo "Adding cron logging to ${SYSLOGNG}..." | tee -a $logfile
    back_up_file /etc/syslog-ng/syslog-ng.conf
    if egrep -q "^destination cron" "${SYSLOGNG}" ; then
        echo "cron entry already exists" | tee -a $logfile
    else
        cat <<EOF >>"${SYSLOGNG}"
destination cron { file("/var/log/cron"); };
log { source(src); filter(f_cron); destination(cron); };
EOF
    fi

    if grep -q 'destination ddrmaint { file("\/usr\/local\/avamar\/var\/ddrmaintlogs\/ddrmaint.log" create_dirs(yes) dir_perm(0750) dir_owner("root") dir_group("admin") owner("root") group("admin") perm(0640)); };' ${SYSLOGNG} ; then
        echo "No changes need to be made for ddrmaint..." | tee -a $logfile
    else
        # Change to destination ddrmaint
        sed -i 's/destination ddrmaint.*$/destination ddrmaint { file("\/usr\/local\/avamar\/var\/ddrmaintlogs\/ddrmaint.log" create_dirs(yes) dir_perm(0750) dir_owner("root") dir_group("admin") owner("root") group("admin") perm(0640)); };/' ${SYSLOGNG}
    fi
    # removing references of news from syslog-ng.conf
    # to remove news errors on syslog start
    if grep -q "filter f_news" /etc/syslog-ng/syslog-ng.conf; then
        Perl -pi -e "\"s/(^filter\ f_news*)/\#\$1/;\"" /etc/syslog-ng/syslog-ng.conf
    else
        echo "No changes need to be made for filter f_news settings..." | tee -a $logfile
    fi
    if grep -q "news, " /etc/syslog-ng/syslog-ng.conf; then
        Perl -pi -e "\"s/(news\,\ )//;\"" /etc/syslog-ng/syslog-ng.conf
    else
        echo "No changes need to be made for news, settings..." | tee -a $logfile
    fi
    if grep -q "destination news" /etc/syslog-ng/syslog-ng.conf; then
        Perl -pi -e "\"s/(^destination\ news*)/\#\$1/;\"" /etc/syslog-ng/syslog-ng.conf
    else
        echo "No changes need to be made for destination news settings..." | tee -a $logfile
    fi
    if grep -q "owner(news" /etc/syslog-ng/syslog-ng.conf; then
        Perl -pi -e "\"s/(\owner\(news*)/\#\$1/;\"" /etc/syslog-ng/syslog-ng.conf
    else
        echo "No changes need to be made for owner(news settings..." | tee -a $logfile
    fi
    if grep -q "log { source(src); filter(f_news" /etc/syslog-ng/syslog-ng.conf; then
        Perl -pi -e "\"s/(^log\ \{\ source\(src\)\;\ filter\(f_news*)/\#\$1/;\"" /etc/syslog-ng/syslog-ng.conf
    else
        echo "No changes need to be made for logging news settings..." | tee -a $logfile
    fi
    /etc/init.d/syslog restart
    /etc/init.d/cron restart
    echo "[DONE]" | tee -a $logfile
fi

##     GEN003080/GEN003180 - Crontab and Cronlog File Permissions
# MOVED from other crontab/cronlog permissions changes up top due to file having its permissions reset after
# the cron restart done in the step right before this
change_file_perms 600 /var/log/cron

# Bug 37945 - avhardening package causes perms issues with /data01/.bash_history file (per esc 4395)
BASH_HISTORY=/data01/.bash_history

# Bug 60391 - Removal of bash_history from system supercedes 37945
if [ -f $BASH_HISTORY ]; then
    echo "Deleting $BASH_HISTORY..." | tee -a $logfile
    /usr/bin/chattr -a $BASH_HISTORY
    rm -f $BASH_HISTORY
    echo "[DONE]" | tee -a $logfile

    # Bug 313855 - root prompt was changed after avhardening was installed.
    # here /etc/bash.bashrc.local is obsolete so we should ignore it
    if [ -f /etc/profile.d/zzz-avamar.sh ]; then
        echo "Clearing /etc/profile.d/zzz-avamar.sh..." | tee -a $logfile
        echo "" > /etc/profile.d/zzz-avamar.sh
        sed -i '/PROMPT_COMMAND/d' $PROFILE
        rm -f /etc/logrotate.d/commlog
        echo "[DONE]" | tee -a $logfile
    fi
fi

# Bug #41572 and #41608 - Accounts have been assigned the same User Identification Number (UID)
## changing the UID of polkituser so it doesn't conflict with the dnsmasq UID, or changing the
## uuidd UID so that it doesn't conflict with the dnsmasq UID.
#
echo "Changing polkituser UID to avoid dnsmasq UID conflict, or changing uuidd UID to avoid dnsmasq UID conflict..." | tee -a $logfile
POLKIT=`grep ^polkituser: /etc/passwd | awk -F: '{print $3}'`
DNSMASQ=`grep ^dnsmasq: /etc/passwd | awk -F: '{print $3}'`
UUIDD=`grep ^uuidd: /etc/passwd | awk -F: '{print $3}'`

if [ -n "$DNSMASQ" ]; then
    if  [ "$POLKIT" == $DNSMASQ ] ; then
        echo "Changing the UID for polkituser..." | tee -a $logfile
        usermod -u 109 polkituser
    elif  [ "$UUIDD" == $DNSMASQ ] ; then
        echo "Changing the UID for uuidd user..." | tee -a $logfile
        usermod -u 109 uuidd
    fi
fi
echo "[DONE]" | tee -a $logfile

#    GEN003060 - Default System Accounts and Cron
echo "Creating and populating /etc/cron.allow..." | tee -a $logfile
CRONALLOW=/etc/cron.allow
if [ ! -e ${CRONALLOW} ]; then
    touch ${CRONALLOW}
    back_up_file ${CRONALLOW}
else
    back_up_file ${CRONALLOW}
fi
for user in root admin
do
    if egrep -q '^${user}' ${CRONALLOW} ; then
        continue
    else
        echo $user >> ${CRONALLOW}
    fi
done
echo "[DONE]" | tee -a $logfile

#    GEN003200 - Cron.deny Permissions | Change perms to cron.deny to 600
CRONDENY=/etc/cron.deny
echo "Setting permissions on ${CRONDENY}..." | tee -a $logfile
change_file_perms 600 ${CRONDENY}

#    GEN001200 - System Command Permissions
echo "Changing system command files permissions and ownerships..." | tee -a $logfile
change_file_owner root:root /etc/ntp.conf
change_file_perms 755 /etc/ntp.conf
echo "[DONE]" | tee -a $logfile

# Esc 3718 - world writeable files
echo "Restricting world-writeable access to files..." | tee -a $logfile
change_file_perms o-w /usr/local/avamar/bin/benchmark
change_file_perms o-w /opt/dell/srvadmin/iws/config/keystore.db.bak
change_file_perms o-w /.avamardata/var/mc/cli_data/prefs/mcclimcs.xml
change_file_perms o-w /.avamardata/var/mc/cli_data/prefs/mccli_logging.properties
change_file_perms o-w /.avamardata/var/mc/cli_data/prefs/prefs.tmp
change_file_perms o-w /.avamardata/var/mc/cli_data/prefs/mccli.xml
change_file_perms o-w /etc/openldap/cacerts.*/cert.pem.orig
change_file_perms o-w /etc/openldap/cacerts/cert.pem.orig
change_file_perms o-w /root/.avamardata/var/mc/cli_data/prefs/mcclimcs.xml
change_file_perms o-w /root/.avamardata/var/mc/cli_data/prefs/mccli_logging.properties
change_file_perms o-w /root/.avamardata/var/mc/cli_data/prefs/prefs.tmp
change_file_perms o-w /root/.avamardata/var/mc/cli_data/prefs/mccli.xml
change_file_perms o-w /data01/home/admin/.avamardata/var/mc/cli_data/prefs/mccli.xml
change_file_perms o-w /data01/home/admin/.avamardata/var/mc/cli_data/prefs/mcclimcs.xml
change_file_perms o-w /data01/home/admin/.avamardata/var/mc/cli_data/prefs/mccli_logging.properties
change_file_perms o-w /data01/home/admin/.avamardata/var/mc/cli_data/prefs/prefs.tmp
change_file_perms o-w /data01/home/dpn/.avamardata/var/mc/cli_data/prefs/mccli.xml
change_file_perms o-w /data01/home/dpn/.avamardata/var/mc/cli_data/prefs/mcclimcs.xml
change_file_perms o-w /data01/home/dpn/.avamardata/var/mc/cli_data/prefs/mccli_logging.properties
change_file_perms o-w /data01/home/dpn/.avamardata/var/mc/cli_data/prefs/prefs.tmp
change_file_perms o-w /data01/avamar/var/mc/server_log/mcsnmp.out
change_file_perms o-w /data01/avamar/var/mc/server_log/mcddrsnmp.out
change_file_perms o-w /data01/avamar/var/*.dat
change_file_perms o-w /data01/avamar/var/change-passwords.log
# Bug 38084 - Don't allow world writeable files and dirs and changing perms to more restrictive on various files
change_file_perms o-w /data01/avamar/var/*/avagent.lck
change_file_perms o-w /data01/avamar/var/avagent.lck
change_file_perms o-w /data01/avamar/var/*.dtb
change_file_perms o-w /data01/avamar/var/*/*.dtb
# Bug 41586 - More world writeable files
change_file_perms o-w /data01/avamar/var/securitytest-*.dtb
change_file_perms o-w /data01/avamar/var/mc/server_log/mcddrsnmp.out
change_file_perms o-w /data01/avamar/var/securitytest.asl.lab.emc.com-*.dtb
change_file_perms o-w /data01/avamar/var/change-passwords.log
change_file_perms o-w /data01/July2012/Script.July/TOC-DB
change_file_perms o-w /usr/local/avamar/etc/ldap.properties
change_file_perms o-w /usr/local/avamar/etc/krb5.conf
change_file_perms o-w /usr/local/avamar/etc/dtlt.properties
change_file_perms o-w /data01/avamar/var
change_file_perms o-w /data01/avamar/var/local
change_file_perms o-w /data01/avamar/var/local/ziptemp
change_file_perms o-w /data01/connectemc/poll
change_file_perms o-w /dev/shm
change_file_perms o-w /var/cache/fonts
change_file_perms o-w /var/tmp/vi.recover
change_file_perms o-w /var/spool/mail
change_file_perms o-w /usr/src/packages/RPMS
change_file_perms o-w /usr/src/packages/RPMS/x86_64
change_file_perms o-w /usr/src/packages/RPMS/noarch
change_file_perms o-w /usr/src/packages/BUILD
change_file_perms o-w /usr/src/packages/SPECS
change_file_perms o-w /usr/src/packages/SRPMS
change_file_perms o-w /usr/src/packages/SOURCES/
change_file_perms 755 /usr/src/packages/SOURCES/
change_file_perms 755 /usr/src/packages/BUILD/
change_file_perms 755 /usr/src/packages/RPMS/
change_file_perms 755 /usr/src/packages/RPMS/x86_64/
change_file_perms 755 /usr/src/packages/RPMS/noarch/
change_file_perms 755 /usr/src/packages/SPECS/
change_file_perms 755 /usr/src/packages/SRPMS
change_file_perms o-w /space/home/admin/.avamardata/var/mc/cli_data/prefs/mccli.xml
change_file_perms o-w /space/home/admin/.avamardata/var/mc/cli_data/prefs/mccli_logging.properties
change_file_perms o-w /space/home/admin/.avamardata/var/mc/cli_data/prefs/prefs.tmp
change_file_perms o-w /space/home/admin/.avamardata/var/mc/cli_data/prefs/mcclimcs.xml
change_file_perms o-w /space/home/admin/searchgsanlogs
change_file_perms o-w /space/avamar/var/mc/server_log/mcddrsnmp.out
change_file_perms o-w /usr/local/avamar/bin/benchmark
change_file_perms o-w /root/.avamardata/var/mc/cli_data/prefs/mccli_logging.properties
change_file_perms o-w /root/.avamardata/var/mc/cli_data/prefs/prefs.tmp
change_file_perms o-w /root/.avamardata/var/mc/cli_data/prefs/mccli.xml
change_file_perms o-w /root/.avamardata/var/mc/cli_data/prefs/mcclimcs.xml
change_file_perms o-w /space/avamar/var
change_file_perms o-w /space/avamar/var/local
change_file_perms o-w /space/avamar/var/local/ziptemp
change_file_perms o-w /data01/connectemc/poll

#   Additional DISA Requirements
change_file_perms o-w /etc/X11/xinit/xinitrc.d/popup.sh

rm -rf /data01/avamar/var/web_avtar
echo "[DONE]" | tee -a $logfile

# Esc 3718 - adding the sticky bit to world writeable directories
echo "Adding the sticky bit to world writeable directories..." | tee -a $logfile
change_file_perms +t /tmp/replicate
change_file_perms +t /root/backups_*/usr/local/avamar/var
#change_file_perms +t /root/backup_upgrade_files.avupswaux2.1/usr/local/avamar/var
#change_file_perms +t /root/backup_upgrade_files.avupswaux2.1/home
#change_file_perms +t /root/backup_upgrade_files.avupswaux2/usr/local/avamar/var
#change_file_perms +t /root/backup_upgrade_files.avupswaux2/home

# Bug 325008 before gen5
[ -d /data01/avamar/var ] && change_file_perms +t /data01/avamar/var
[ -d /data01/avamar/var/local ] && change_file_perms +t /data01/avamar/var/local
[ -d /data01/avamar/var/local/ziptemp ] && change_file_perms +t /data01/avamar/var/local/ziptemp
# since gen5
[ -d /usr/local/avamar/var ] && change_file_perms +t /usr/local/avamar/var
[ -d /usr/local/avamar/var/local ] && change_file_perms +t /usr/local/avamar/var/local
[ -d /usr/local/avamar/var/local/ziptemp ] && change_file_perms +t /usr/local/avamar/var/local/ziptemp

echo "[DONE]" | tee -a $logfile

postfix_installed=`rpm -q postfix | grep -v 'not installed'`
    if [[ -n "$postfix_installed" ]]; then
    #Bug 38757 - Stopping excessive services from running
    echo "Cutting down on a few excessive services..." | tee -a $logfile
    #Check if postfix is running
    if P=$(service postfix status) ; then
        service postfix stop
        chkconfig postfix off
    fi
    echo "[DONE]" | tee -a $logfile
fi

#    GEN001000/Bug 41590 - There are remote consoles defined (file already backed up earlier)
echo "Removing all remote consoles except tty1 in ${SECURETTY}..." | tee -a $logfile
Perl -i.$savext -npe "'s/^(tty[2-9]|tty[1-9][0-9]|vc\/\d+)$/\#\$1/;'" ${SECURETTY}
echo "[DONE]" | tee -a $logfile

#Bug 200802 & 251615
echo "Hardening file permissions in /usr/bin..." | tee -a $logfile

# Bug 316366 - esc 36350:require update to /etc/sudoers file to support ADMe running as admin
# To chown should happen before chmod, otherwise, the 'Set-User-Id' permission will be removed when chmod
change_file_owner root:admin /usr/bin/crontab
change_file_perms 4750 /usr/bin/crontab

change_file_owner root:admin /usr/bin/at
change_file_perms 4750 /usr/bin/at

change_file_perms 755 /sbin/mount.nfs
change_file_perms 4750 /usr/bin/fusermount
change_file_perms 755 /usr/bin/vlock
change_file_perms 755 /usr/bin/wall
change_file_perms 755 /usr/bin/write
change_file_perms 4750 /sbin/pccardctl
change_file_perms 755 /usr/sbin/zypp-refresh-wrapper
# Bug 310783
change_file_perms 4755 /usr/bin/ping
change_file_perms 4755 /usr/bin/ping6
echo "[DONE]" | tee -a $logfile

#Bug 253225 - SUDO
change_file_owner root:root /usr/local/avamar/bin
change_file_owner root:root /usr/local/avamar/lib/admin
