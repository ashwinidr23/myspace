#/bin/bash

if [ $# -ne 1 ]
then
    echo "Enter a valid Shell email id"
    exit 1
fi

#check if it is valid shell email id

email="$1"
echo "$email"| grep -qi "@shell.com"
if [ $? -ne 0 ]; then
        echo "Enter a valid Shell email id "
        exit 1
fi

# Assign arguments to variables
file_path=/etc/httpd/conf/httpd.conf
host_ip=`hostname -i`
host_name=`hostname -f`

# Print the values (for debugging )
echo "Hostname: $host_name"
echo "IP Address: $host_ip"
echo "Email: $email"


echo "running auto ssl cert renewal script"

echo "exporting proxy env variable"
PROXY=zproxy-global.shell.com:80
export no_proxy=.shell.com
export http_proxy=$PROXY
export https_proxy=$PROXY

echo "loading required python version"
source_env(){
source '/glb/apps/hpc/EasyBuild/Public/Lmod/etc/profile.d/z01_lmod-hpcti.sh'
}
source_env
module load HpctiSoftwareStack/PRODUCTION
module load Python/3.8.2-GCCcore-9.3.0

echo $file_path
echo "updating httpd.conf file with ip address"
# Check if the file exists
if [ ! -f ${file_path} ]; then
    echo "File $file_path not found!"
    exit 1
fi

# Define the VirtualHost block with the provided IP address
virtualhost_block="<VirtualHost $host_ip:80>
        ServerName aewnl00392hsmg.linux.shell.com
        DocumentRoot /var/www/acme
        RewriteEngine on
        RewriteCond %{SERVER_NAME} =aewnl00392hsmg.linux.shell.com
        RewriteRule ^ https://%{SERVER_NAME}%{REQUEST_URI} [END,NE,R=permanent]
</VirtualHost>"

# Check if the VirtualHost block is already present in the file
if grep -q "<VirtualHost $host_ip:80>" "$file_path"; then
    echo "VirtualHost block with IP $host_ip already exists in $file_path."
else
    # Append the VirtualHost block to the file
    echo "Appending VirtualHost block to $file_path."
    echo "$virtualhost_block" >> "$file_path"
    echo "VirtualHost block added."
fi

echo "installing certbot"
dnf install -y augeas-libs
python -m venv /opt/certbot
/opt/certbot/bin/pip install --upgrade pip
/opt/certbot/bin/pip install certbot certbot-apache
/opt/certbot/bin/pip install 'urllib3<2.0'
/opt/certbot/bin/pip install certifi

# check id the soft link already exists
link_name=/usr/bin/certbot

if [ -L "$link_name" ]; then
    echo "Symbolic link $link_name already exists."
else
    ln -s /opt/certbot/bin/certbot /usr/bin/certbot
fi

echo "exporting ca bundle"
cat /etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem /etc/httpd/conf.d/$host_name.crt > /opt/certbot/lib/python3.8/site-packages/certifi/cacert.pem

echo "getting certificate from certbot"
echo "certbot certonly -n --preferred-challenges http --key-type rsa -d $host_name -m $email --agree-tos --server https://cms-prod.appviewx.shell.com:31443/avxapi/SSLTLS-ShellPrivateType1EUPrimaryIssuingCA/acme/directory"
certbot certonly -n --standalone --preferred-challenges http --key-type rsa -d $host_name -m $email --agree-tos --server https://cms-prod.appviewx.shell.com:31443/avxapi/SSLTLS-ShellPrivateType1EUPrimaryIssuingCA/acme/directory

echo "creating certbot cron job"

echo "source '/glb/apps/hpc/EasyBuild/Public/Lmod/etc/profile.d/z01_lmod-hpcti.sh'
module load HpctiSoftwareStack/PRODUCTION
module load Python/3.8.2-GCCcore-9.3.0
/opt/certbot/bin/python -c 'import random; import time; time.sleep(random.random() * 3600)' && certbot renew -q
cp /etc/letsencrypt/live/$host_name/cert.pem /etc/httpd/conf.d/$host_name.crt
cp /etc/letsencrypt/live/$host_name/privkey.pem /etc/httpd/conf.d/ck
chown s_bpac00:g_bpa2prod /etc/httpd/conf.d/ck
chown s_bpac00:g_bpa2prod /etc/httpd/conf.d/$host_name.crt
" > /usr/local/sbin/certbot.sh
chmod 755 /usr/local/sbin/certbot.sh

echo "0,0,12 * * * root /usr/local/sbin/certbot.sh  >/dev/null 2>&1" > /etc/cron.d/certbot

echo "copying certs"
cp /etc/letsencrypt/live/$host_name/cert.pem /etc/httpd/conf.d/$host_name.crt
cp /etc/letsencrypt/live/$host_name/privkey.pem /etc/httpd/conf.d/ck

echo "updating ownership of certs"
chown s_bpac00:g_bpa2prod /etc/httpd/conf.d/ck
chown s_bpac00:g_bpa2prod /etc/httpd/conf.d/$host_name.crt

echo "done"
exit 0
