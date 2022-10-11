
PATH_GOAV=/home/admin/tmp
PATH_SECURIZACION=/home/admin/tmp/TFN_securizacion_proxy

### COPIA DE SEGURIDAD DE FICHEROS ############
################################################

#$PATH_GOAV/goav proxy upload --local $PATH_SECURIZACION/backup_files.sh --remote /tmp/backup_files.sh -n
#$PATH_GOAV/goav proxy exec "chmod 744 /tmp/backup_files.sh" -n
#$PATH_GOAV/goav proxy exec "/tmp/backup_files.sh" -n


#### hardening.sh ##############################
################################################

#$PATH_GOAV/goav proxy upload --local $PATH_SECURIZACION/hardening.sh --remote /tmp/hardening.sh -n
#$PATH_GOAV/goav proxy exec "chown root:root /tmp/hardening.sh" -n
#$PATH_GOAV/goav proxy exec "chmod 700 /tmp/hardening.sh" -n
#$PATH_GOAV/goav proxy exec "/tmp/hardening.sh" -n


#### POLITICA DE PASSWORDS #####################
################################################

#PATH_GOAV/goav proxy exec "sed -i.back 's/sed -i.back 's7"PASS_MAX_DAYS   99999"7"PASS_MAX_DAYS   99999"7g' login.defs-test
sed -i.back 's/PASS_MAX_DAYS   99999/PASS_MAX_DAYS   90/g' login.defs-test
sed -i.back 's/PASS_MIN_DAYS   0/PASS_MIN_DAYS   6/g' login.defs-test
sed -i.back 's7PASS_WARN_AGE   7/PASS_WARN_AGE   30/g' login.defs-test

#$PATH_GOAV/goav proxy exec "useradd -D -f 60" -n
#$PATH_GOAV/goav proxy exec "touch /etc/security/opasswd" -n
#$PATH_GOAV/goav proxy exec "chmod 600 /etc/security/opasswd" -n

#$PATH_GOAV/goav proxy upload --local $PATH_SECURIZACION/common-password --remote /etc/pam.d/common-password -n
#$PATH_GOAV/goav proxy upload --local $PATH_SECURIZACION/common-auth --remote /etc/pam.d/common-auth -n
#$PATH_GOAV/goav proxy upload --local $PATH_SECURIZACION/common-account --remote /etc/pam.d/common-account -n
