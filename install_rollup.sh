
PATH_GOAV=/home/admin/tmp

$PATH_GOAV/goav proxy exec "mkdir /usr/local/tmp/ospatches" -n
$PATH_GOAV/goav proxy upload --local /tmp/sec_os_update_proxy-2022-R3-v4.tgz --remote /usr/local/tmp/ospathes/sec_os_update_proxy-2022-R3-v4.tgz -n

$PATH_GOAV/goav proxy exec "tar -xvzf /usr/local/tmp/ospathes/sec_os_update_proxy-2022-R3-v4.tgz" -n
$PATH_GOAV/goav proxy exec "perl sec_install_os_errata_sles.pl --version" -n