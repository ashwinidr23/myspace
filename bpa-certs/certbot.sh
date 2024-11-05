source '/glb/apps/hpc/EasyBuild/Public/Lmod/etc/profile.d/z01_lmod-hpcti.sh'
module load HpctiSoftwareStack/PRODUCTION
module load Python/3.8.2-GCCcore-9.3.0
/opt/certbot/bin/python -c 'import random; import time; time.sleep(random.random() * 3600)' && certbot renew -q
cp /etc/letsencrypt/live/housky-n-gp401h01.americas.shell.com/cert.pem /etc/httpd/conf.d/housky-n-gp401h01.americas.shell.com.crt
cp /etc/letsencrypt/live/housky-n-gp401h01.americas.shell.com/privkey.pem /etc/httpd/conf.d/ck
chown s_bpac00:g_bpa2prod /etc/httpd/conf.d/ck
chown s_bpac00:g_bpa2prod /etc/httpd/conf.d/housky-n-gp401h01.americas.shell.com.crt