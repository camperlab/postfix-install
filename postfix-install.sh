#!/bin/bash
# Copyright (c) 2021 CamperLab
# requirements Ubuntu 20.04
#
# cloudflare.com setup
# A  @             {ip_address}
# -----------------------------
# A  mail          {ip_address} (dns_only)
# -----------------------------
# A  postfixadmin  {ip_address} (dns_only)
# -----------------------------
# MX {domain}      mail.{domain}
# -----------------------------
#

echo "Please enter mail domain name (example.com)"
read domain

# set hostname
sudo hostnamectl set-hostname mail.$domain

# install postfix
echo "postfix	postfix/mailname string $domain" | debconf-set-selections
echo "postfix postfix/main_mailer_type string 'Internet Site'" | debconf-set-selections
apt update
apt -y -qq -o=Dpkg::Use-Pty=0 install curl postfix nginx ufw certbot python3-certbot-nginx dovecot-core dovecot-imapd dovecot-mysql \
 dovecot-pop3d dovecot-lmtpd mariadb-server mariadb-client acl postfix-mysql php7.4-fpm php7.4-imap php7.4-mbstring \
 php7.4-mysql php7.4-json php7.4-curl php7.4-zip php7.4-xml php7.4-bz2 php7.4-intl php7.4-gmp pwgen expect
# allow ports
ufw allow 25/tcp && ufw allow 80,443,587,465,143,993/tcp && ufw allow 110,995/tcp
# increase attachment size
postconf -e message_size_limit=52428800
postconf -e "inet_protocols = ipv4"
systemctl restart postfix

echo "server {
  listen 80;
  listen [::]:80;
  server_name mail.$domain;

  root /var/www/html/;

  location ~ /.well-known/acme-challenge {
    allow all;
  }
}" > /etc/nginx/sites-available/mail.$domain.conf

ln -s /etc/nginx/sites-available/mail.$domain.conf /etc/nginx/sites-enabled/mail.$domain.conf
systemctl reload nginx
certbot certonly -a nginx --agree-tos --no-eff-email --staple-ocsp --email admin@$domain -d mail.$domain

submission="submission     inet     n    -    y    -    -    smtpd\n \
 -o syslog_name=postfix/submission\n \
 -o smtpd_tls_security_level=encrypt\n \
 -o smtpd_tls_wrappermode=no\n \
 -o smtpd_sasl_auth_enable=yes\n \
 -o smtpd_relay_restrictions=permit_sasl_authenticated,reject\n \
 -o smtpd_recipient_restrictions=permit_mynetworks,permit_sasl_authenticated,reject\n \
 -o smtpd_sasl_type=dovecot\n \
 -o smtpd_sasl_path=private/auth"
sed -i  "/#submission inet n       -       y       -       -       smtpd/i $submission" /etc/postfix/master.cf

smtps="smtps     inet  n       -       y       -       -       smtpd\n \
 -o syslog_name=postfix/smtps\n \
 -o smtpd_tls_wrappermode=yes\n \
 -o smtpd_sasl_auth_enable=yes\n \
 -o smtpd_relay_restrictions=permit_sasl_authenticated,reject\n \
 -o smtpd_recipient_restrictions=permit_mynetworks,permit_sasl_authenticated,reject\n \
 -o smtpd_sasl_type=dovecot\n \
 -o smtpd_sasl_path=private/auth"
sed -i  "/#smtps     inet  n       -       y       -       -       smtpd/i $smtps" /etc/postfix/master.cf

sed -i 's#smtpd_tls_cert_file=/etc/ssl/certs/ssl-cert-snakeoil.pem##g' /etc/postfix/main.cf
sed -i 's#smtpd_tls_key_file=/etc/ssl/private/ssl-cert-snakeoil.key##g' /etc/postfix/main.cf
sed -i 's#smtpd_tls_security_level=may##g' /etc/postfix/main.cf
sed -i 's#smtp_tls_CApath=/etc/ssl/certs##g' /etc/postfix/main.cf
sed -i 's#smtp_tls_security_level=may##g' /etc/postfix/main.cf
sed -i 's#smtp_tls_session_cache_database = btree:\${data_directory}/smtp_scache##g' /etc/postfix/main.cf

# setup tls settings in main.cf

ssl="# Enable TLS Encryption when Postfix receives incoming emails\n\
smtpd_tls_cert_file=/etc/letsencrypt/live/mail.$domain/fullchain.pem\n\
smtpd_tls_key_file=/etc/letsencrypt/live/mail.$domain/privkey.pem\n\
smtpd_tls_security_level = may\n\
smtpd_tls_loglevel = 1\n\n\
# Enable TLS Encryption when Postfix sends outgoing emails \
\nsmtpd_tls_session_cache_database = btree:\${data_directory}/smtpd_scache\n\
smtp_tls_security_level = may\n\
smtp_tls_loglevel = 1\n\
smtp_tls_session_cache_database = btree:\${data_directory}/smtp_scache\n\n\
# Enforce TLSv1.3 or TLSv1.2 \
\nsmtpd_tls_mandatory_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1\n\
smtpd_tls_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1\n\
smtp_tls_mandatory_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1\n\
smtp_tls_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1"
sed -i "/# TLS parameters/i $ssl" /etc/postfix/master.cf
sed -i 's/# TLS parameters//g' /etc/postfix/master.cf

# add dovecot support to main.cf
sed -i -e '$amailbox_transport = lmtp:unix:private/dovecot-lmtp' /etc/postfix/main.cf
sed -i -e '$asmtputf8_enable = no' /etc/postfix/main.cf

systemctl restart postfix

# setup dovecot settings in dovecot.conf
sudo adduser dovecot mail
sed -i "/## Dovecot configuration file/a protocols = imap pop3 lmtp" /etc/dovecot/dovecot.conf
# 10-main.conf
sed -i "s?mail_location = mbox:~/mail:INBOX=/var/mail/%u?mail_location = maildir:~\/Maildir \n# PLACEHOLDER ?g" /etc/dovecot/conf.d/10-mail.conf
# 10-master.conf
sed -i "s#unix_listener lmtp {#unix_listener /var/spool/postfix/private/dovecot-lmtp {#g" /etc/dovecot/conf.d/10-master.conf
sed -i "/dovecot-lmtp {/a \ \ \ mode = 0600\n   user = postfix\n   group = postfix" /etc/dovecot/conf.d/10-master.conf
unix_listener="unix_listener /var/spool/postfix/private/auth { \n \ \ mode = 0600\n   user = postfix\n   group = postfix"
sed -i "s#unix_listener auth-userdb {#$unix_listener#g" /etc/dovecot/conf.d/10-master.conf
# 10-auth.conf
sed -i 's/#disable_plaintext_auth = yes/disable_plaintext_auth = yes/g' /etc/dovecot/conf.d/10-auth.conf
sed -i 's/#auth_username_format = %Lu/auth_username_format = %u/g' /etc/dovecot/conf.d/10-auth.conf
sed -i 's/auth_mechanisms = plain/auth_mechanisms = plain login/g' /etc/dovecot/conf.d/10-auth.conf
# 10-ssl.conf
sed -i 's/ssl = yes/ssl = required/g' /etc/dovecot/conf.d/10-ssl.conf
sed -i "s#ssl_cert = </etc/dovecot/private/dovecot.pem#ssl_cert = </etc/letsencrypt/live/mail.$domain/fullchain.pem#g" \
 /etc/dovecot/conf.d/10-ssl.conf
sed -i "s#ssl_key = </etc/dovecot/private/dovecot.key#ssl_key = </etc/letsencrypt/live/mail.$domain/privkey.pem#g" \
 /etc/dovecot/conf.d/10-ssl.conf
sed -i 's/#ssl_prefer_server_ciphers = no/ssl_prefer_server_ciphers = yes/g' /etc/dovecot/conf.d/10-ssl.conf
sed -i -e '$assl_min_protocol = TLSv1.2' /etc/dovecot/conf.d/10-ssl.conf
# 15-mailboxes.conf
sed -i "/mailbox Drafts {/a \ \ \ \ auto = create" /etc/dovecot/conf.d/15-mailboxes.conf
sed -i "/mailbox Junk {/a \ \ \ \ auto = create" /etc/dovecot/conf.d/15-mailboxes.conf
sed -i "/mailbox Trash {/a \ \ \ \ auto = create" /etc/dovecot/conf.d/15-mailboxes.conf

systemctl restart postfix dovecot

# automatic renew certificate
crontab -l | { cat; echo "@daily certbot renew --quiet && systemctl reload postfix dovecot nginx"; } | crontab -

systemctl restart dovecot
sudo mkdir -p /etc/systemd/system/dovecot.service.d/

echo "[Service]
Restart=always
RestartSec=5s" > /etc/systemd/system/dovecot.service.d/restart.conf

systemctl daemon-reload
pkill dovecot

systemctl start mariadb
systemctl enable mariadb

MYSQL_PASSWORD=$(pwgen -- 16 1)

expect -c "
set timeout 10
spawn mysql_secure_installation
expect \"Enter current password for root (enter for none):\"
send \"$MYSQL_PASSWORD\r\"
expect \"Set root password?\"
send \"n\r\"
expect \"Remove anonymous users?\"
send \"y\r\"
expect \"Disallow root login remotely?\"
send \"y\r\"
expect \"Remove test database and access to it?\"
send \"y\r\"
expect \"Reload privilege tables now?\"
send \"y\r\"
expect eof
"

echo "mysql: root / $MYSQL_PASSWORD" > passwords.txt

apt -y -qq -o=Dpkg::Use-Pty=0 install dbconfig-no-thanks
apt -y -qq -o=Dpkg::Use-Pty=0 install postfixadmin
apt -y -qq -o=Dpkg::Use-Pty=0 remove dbconfig-no-thanks

POSTFIX_DB_PASSWORD=$(pwgen -- 16 1)

expect -c "
set timeout 10
spawn dpkg-reconfigure postfixadmin -freadline
expect \"Reinstall database for postfixadmin?\"
send \"yes\r\"
expect \"Connection method for MySQL database of postfixadmin\"
send \"1\r\"
expect \"Authentication plugin for MySQL database:\"
send \"1\r\"
expect \"MySQL database name for postfixadmin:\"
send \"postfixadmin\r\"
expect \"MySQL username for postfixadmin:\"
send \"postfixadmin@localhost\r\"
expect \"MySQL application password for postfixadmin:\"
send \"$POSTFIX_DB_PASSWORD\r\"
expect \"Password confirmation:\"
send \"$POSTFIX_DB_PASSWORD\r\"
expect \"Name of the database's administrative user:\"
send \"root\r\"
expect eof
"

sed -i -e "\$apostfix db: postfixadmin / $POSTFIX_DB_PASSWORD" passwords.txt
sed -i "s/dbc_dbtype='mysql'/dbc_dbtype='mysqli'/g" /etc/dbconfig-common/postfixadmin.conf
sed -i "s/\$dbtype='mysql';/\$dbtype='mysqli';/g" /etc/postfixadmin/dbconfig.inc.php
mkdir /usr/share/postfixadmin/templates_c
setfacl -R -m u:www-data:rwx /usr/share/postfixadmin/templates_c/

echo "server {
  listen 80;
  listen [::]:80;
  server_name postfixadmin.$domain;

  root /usr/share/postfixadmin/public/;
  index index.php index.html;

  access_log /var/log/nginx/postfixadmin_access.log;
  error_log /var/log/nginx/postfixadmin_error.log;

  location / {
    try_files \$uri \$uri/ /index.php;
  }

  location ~ ^/(.+\.php)$ {
    include snippets/fastcgi-php.conf;
    fastcgi_pass unix:/var/run/php/php7.4-fpm.sock;
  }
}" > /etc/nginx/sites-available/postfixadmin.$domain.conf

ln -s /etc/nginx/sites-available/postfixadmin.$domain.conf /etc/nginx/sites-enabled/postfixadmin.$domain.conf
systemctl reload nginx
certbot --nginx --no-redirect --agree-tos --hsts --staple-ocsp --email admin@$domain -d postfixadmin.$domain

echo "<?php
\$CONF['encrypt'] = 'dovecot:ARGON2I';
\$CONF['dovecotpw'] = '/usr/bin/doveadm pw -r 5';
if (@file_exists('/usr/bin/doveadm')) {
    \$CONF['dovecotpw'] = '/usr/bin/doveadm pw -r 5';
}" > /usr/share/postfixadmin/config.local.php
ln -s /usr/share/postfixadmin/config.local.php /etc/postfixadmin/config.local.php

mysql -u root -p$MYSQL_PASSWORD -e "alter database postfixadmin collate ='utf8_general_ci';"
setfacl -R -m u:www-data:rx /etc/letsencrypt/live/ /etc/letsencrypt/archive/

POSTFIX_ADMIN_PASSWORD=12$(pwgen -- 16 1)

FORM_DATA="form=setuppw\
&setup_password=$POSTFIX_ADMIN_PASSWORD\
&setup_password2=$POSTFIX_ADMIN_PASSWORD\
&submit=Generate+password+hash"
curl -d $FORM_DATA -X POST http://postfixadmin.$domain/setup.php > postfixadmin.txt
POSTFIX_PASSWORD_STRING=$(grep -oP "(?<=<pre>).*?(?=</pre>)" postfixadmin.txt) && rm postfixadmin.txt
sed -i -e "\$a$POSTFIX_PASSWORD_STRING" /usr/share/postfixadmin/config.local.php

FORM_DATA_2="form=createadmin&\
setup_password=$POSTFIX_ADMIN_PASSWORD\
&username=admin%40$domain\
&password=$POSTFIX_ADMIN_PASSWORD\
&password2=$POSTFIX_ADMIN_PASSWORD\
&submit=Add+Admin"

curl -d $FORM_DATA_2 -X POST http://postfixadmin.$domain/setup.php > postfixadmin.txt
sed -i -e "\$apostfixadmin: admin@$domain / $POSTFIX_ADMIN_PASSWORD" passwords.txt
rm postfixadmin.txt

virtual_mailboxes="virtual_mailbox_domains = proxy:mysql:/etc/postfix/sql/mysql_virtual_domains_maps.cf\n\
virtual_mailbox_maps =\n\
   proxy:mysql:/etc/postfix/sql/mysql_virtual_mailbox_maps.cf,\n\
   proxy:mysql:/etc/postfix/sql/mysql_virtual_alias_domain_mailbox_maps.cf\n\
virtual_alias_maps =\n\
   proxy:mysql:/etc/postfix/sql/mysql_virtual_alias_maps.cf,\n\
   proxy:mysql:/etc/postfix/sql/mysql_virtual_alias_domain_maps.cf,\n\
   proxy:mysql:/etc/postfix/sql/mysql_virtual_alias_domain_catchall_maps.cf\n\
virtual_transport = lmtp:unix:private/dovecot-lmtp\n\
virtual_mailbox_base = /var/vmail\n\
virtual_minimum_uid = 2000\n\
virtual_uid_maps = static:2000\n\
virtual_gid_maps = static:2000"

postconf -e "mydestination = \$myhostname, localhost.\$mydomain, localhost"

sed -i -e "\$a $virtual_mailboxes" /etc/postfix/main.cf

mkdir /etc/postfix/sql/

echo "user = postfixadmin
password = $POSTFIX_DB_PASSWORD
hosts = localhost
dbname = postfixadmin
query = SELECT domain FROM domain WHERE domain='%s' AND active = '1'
#query = SELECT domain FROM domain WHERE domain='%s'
#optional query to use when relaying for backup MX
#query = SELECT domain FROM domain WHERE domain='%s' AND backupmx = '0' AND active = '1'
#expansion_limit = 100" > /etc/postfix/sql/mysql_virtual_domains_maps.cf

echo "user = postfixadmin
password = $POSTFIX_DB_PASSWORD
hosts = localhost
dbname = postfixadmin
query = SELECT maildir FROM mailbox WHERE username='%s' AND active = '1'
#expansion_limit = 100" > /etc/postfix/sql/mysql_virtual_mailbox_maps.cf

echo "user = postfixadmin
password = $POSTFIX_DB_PASSWORD
hosts = localhost
dbname = postfixadmin
query = SELECT maildir FROM mailbox,alias_domain WHERE alias_domain.alias_domain = '%d' and\
 mailbox.username = CONCAT('%u', '@', alias_domain.target_domain) AND mailbox.active = 1 AND alias_domain.active='1'
" > /etc/postfix/sql/mysql_virtual_alias_domain_mailbox_maps.cf

echo "user = postfixadmin
password = $POSTFIX_DB_PASSWORD
hosts = localhost
dbname = postfixadmin
query = SELECT goto FROM alias WHERE address='%s' AND active = '1'
#expansion_limit = 100" > /etc/postfix/sql/mysql_virtual_alias_maps.cf

echo "user = postfixadmin
password = $POSTFIX_DB_PASSWORD
hosts = localhost
dbname = postfixadmin
query = SELECT goto FROM alias,alias_domain WHERE alias_domain.alias_domain = '%d' and\
 alias.address = CONCAT('%u', '@', alias_domain.target_domain) AND alias.active = 1 AND alias_domain.active='1'
" > /etc/postfix/sql/mysql_virtual_alias_domain_maps.cf

echo "# handles catch-all settings of target-domain
user = postfixadmin
password = $POSTFIX_DB_PASSWORD
hosts = localhost
dbname = postfixadmin
query = SELECT goto FROM alias,alias_domain WHERE alias_domain.alias_domain = '%d'\
and alias.address = CONCAT('@', alias_domain.target_domain) AND alias.active = 1 AND alias_domain.active='1'
" > /etc/postfix/sql/mysql_virtual_alias_domain_catchall_maps.cf

chmod 0640 /etc/postfix/sql/*
setfacl -R -m u:postfix:rx /etc/postfix/sql/
systemctl restart postfix
adduser vmail --system --group --uid 2000 --disabled-login --no-create-home
mkdir /var/vmail/
chown vmail:vmail /var/vmail/ -R
sed -i "s?# PLACEHOLDER?mail_home = /var/vmail/%d/%n/?g" /etc/dovecot/conf.d/10-mail.conf
# 10-auth.conf
sed -i 's/!include auth-system.conf.ext/#!include auth-system.conf.ext/g' /etc/dovecot/conf.d/10-auth.conf
sed -i 's/#!include auth-sql.conf.ext/!include auth-sql.conf.ext/g' /etc/dovecot/conf.d/10-auth.conf
sed -i -e '$aauth_debug = yes\nauth_debug_passwords = yes' /etc/dovecot/conf.d/10-auth.conf

echo "driver = mysql
connect = host=localhost dbname=postfixadmin user=postfixadmin password=$POSTFIX_DB_PASSWORD
default_pass_scheme = ARGON2I
password_query = SELECT username AS user,password FROM mailbox WHERE username = '%u' AND active='1'
user_query = SELECT maildir, 2000 AS uid, 2000 AS gid FROM mailbox WHERE username = '%u' AND active='1'
iterate_query = SELECT username AS user FROM mailbox" > /etc/dovecot/dovecot-sql.conf.ext

systemctl restart dovecot