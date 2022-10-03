### COPIA DE SEGURIDAD DE FICHEROS ############
################################################

/home/admin/tmp/goav proxy upload --local /home/admin/tmp/backup_files.sh --remote /tmp/backup_files.sh -n
/home/admin/tmp/goav proxy exec "chmod 744 /tmp/backup_files.sh" -n
/home/admin/tmp/goav proxy exec "/tmp/backup_files.sh" -n


#### hardening.sh ##############################
################################################

/home/admin/tmp/goav proxy upload --local /usr/local/avamar/lib/admin/security/hardening.sh --remote /tmp/hardening.sh -n
/home/admin/tmp/goav proxy exec "chmod 700 /tmp/hardening.sh" -n
/home/admin/tmp/goav proxy exec "/tmp/hardening.sh" -n


#### POLITICA DE PASSWORDS #####################
################################################

/home/admin/tmp/goav proxy exec "useradd -D -f 60" -n
/home/admin/tmp/goav proxy exec "touch /etc/security/opasswd" -n
/home/admin/tmp/goav proxy exec "chmod 600 /etc/security/opasswd" -n

/home/admin/tmp/goav proxy upload --local /home/admin/tmp/proxy-files/common-password --remote /etc/pam.d/common-password
/home/admin/tmp/goav proxy upload --local /home/admin/tmp/proxy-files/common-auth --remote /etc/pam.d/common-auth
/home/admin/tmp/goav proxy upload --local /home/admin/tmp/proxy-files/common-account --remote /etc/pam.d/common-account