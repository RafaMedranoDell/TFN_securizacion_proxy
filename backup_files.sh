cp -p /etc/ssh/sshd_config /etc/ssh/sshd_config.`date +%Y%m%d`
cp -p /etc/profile /etc/profile.`date +%Y%m%d`
cp -p /etc/login.defs /etc/login.defs.`date +%Y%m%d`
cp -p /etc/default/useradd /etc/default/useradd.`date +%Y%m%d`
cp -p /etc/pam.d/common-password /etc/pam.d/common-password.`date +%Y%m%d`
cp -p /etc/pam.d/common-auth /etc/pam.d/common-auth.`date +%Y%m%d`
cp -p /etc/pam.d/common-account /etc/pam.d/common-account.`date +%Y%m%d`
