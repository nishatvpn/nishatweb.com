#!/bin/bash
apt-get update -y
cat << 'SSHCON' > /root/sshcon.php
<?php
error_reporting(E_ERROR | E_PARSE);
ini_set('display_errors', '1');

$DB_host = '162.253.155.198';
$DB_user = 'nishatwp_vpn';
$DB_pass = 'nishatwp_vpn';
$DB_name = 'nishatwp_vpn';

$mysqli = new MySQLi($DB_host,$DB_user,$DB_pass,$DB_name);
if ($mysqli->connect_error) {
    die('Error : ('. $mysqli->connect_errno .') '. $mysqli->connect_error);
}


$data = '';
$premium = "user_duration > 0 AND is_freeze='0'";

$query = $mysqli->query("SELECT * FROM users
WHERE ".$premium." ORDER by user_id DESC");
if($query->num_rows > 0)
{
	while($row = $query->fetch_assoc())
	{
		$data .= '';
		$username = $row['user_name'];
		
		$password = $row['user_pass'];
		
		
		$data .= '/usr/sbin/useradd -p $(openssl passwd -1 '.$password.') -M '.$username.';'.PHP_EOL;
	}
}
$location = '/root/active.sh';
$fp = fopen($location, 'w');
fwrite($fp, $data) or die("Unable to open file!");
fclose($fp);


#In-Active and Invalid Accounts
$data2 = '';
$premium_deactived = "user_duration < 1 AND is_freeze > 0";

$query2 = $mysqli->query("SELECT * FROM users 
WHERE ".$premium_deactived."");
if($query2->num_rows > 0)
{
	while($row2 = $query2->fetch_assoc())
	{
		$data2 .= '';
		$toadd = $row2['user_name'];	
		$data2 .= '/usr/sbin/userdel '.$toadd.''.PHP_EOL;
	}
}
$location2 = '/root/inactive.sh';
$fp = fopen($location2, 'w');
fwrite($fp, $data2) or die("Unable to open file!");
fclose($fp);

$mysqli->close();
?>
SSHCON

DEBIAN_FRONTEND=noninteractive apt-get full-upgrade -q -y -u  -o Dpkg::Options::="--force-confdef" --allow-downgrades --allow-remove-essential --allow-change-held-packages --allow-unauthenticated
apt-get install screen sudo mysql-client nano fail2ban unzip apache2 build-essential curl build-essential libwrap0-dev libpam0g-dev libdbus-1-dev libreadline-dev libnl-route-3-dev libprotobuf-c0-dev libpcl1-dev libopts25-dev autogen libgnutls28-dev libseccomp-dev libhttp-parser-dev php libapache2-mod-php -y
sed -i 's/Listen 80/Listen 81/g' /etc/apache2/ports.conf
service apache2 restart

sudo apt-get install ocserv gnutls-bin -y
sudo cp /lib/systemd/system/ocserv.service /etc/systemd/system/ocserv.service
sed -i 's/Requires=ocserv.socket/#Requires=ocserv.socket/g' /etc/systemd/system/ocserv.service
sed -i 's/Also=ocserv.socket/#Also=ocserv.socket/g' /etc/systemd/system/ocserv.service
sudo systemctl daemon-reload
sudo systemctl stop ocserv.socket
sudo systemctl disable ocserv.socket

echo "export LD_LIBRARY_PATH=/opt/lib/:/opt/lib64/">> /etc/profile
echo 'export PATH=$PATH:/opt/bin'>> /etc/profile
source /etc/profile
rm -rf  /etc/ocserv
mkdir /etc/ocserv

echo '-----BEGIN CERTIFICATE-----
MIICyjCCAbKgAwIBAgIUDSSmTL8bWZDYAPA1NSuRzh3K90cwDQYJKoZIhvcNAQEL
BQAwDzENMAsGA1UEAwwEc2c2NjAeFw0xOTA5MTExMDI4NDVaFw0yOTA5MDgxMDI4
NDVaMA8xDTALBgNVBAMMBHNnNjYwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
AoIBAQDcMijbR6JknWiALMBUN4B3q6YXUgWMrMTuKztKluST1I1vbolqGvhMH/X8
CKNl/aYUsjZX+9AjHi/3qKW9j3AsvOD+IT/rbNd8xHXEVZ/EbxQYVuc2xpgjg7r+
naO63eOHZ5lWmbsKyimv8mjZOBQaPJEsMaSxBAEF9XKYy5duIgAEaRAT4Ugpfgmi
CL4Pl0YCls6LMlKp8Pm29IPXygeRNXxKhITc4SYuUy/CejDtiSkom6CpCg7aFzpi
DjppfyFpCAwjhtU4om6ICezhJcWk79ZovyLKZDp6KPGSvFW2UVyw5vOFjr0RybIL
15aunuq1qGqmFoshhjRKHQ9w8lbNAgMBAAGjHjAcMAkGA1UdEwQCMAAwDwYDVR0R
BAgwBoIEc2c2NjANBgkqhkiG9w0BAQsFAAOCAQEAjg15aE/DWgjgMab4frVSjfyg
pXCReeFGiJDsuPYFZpRKz2DosjCnsxc2KjN5MHlUod5EeX5IcSXb0WzDKp0J36YM
FlhsZCxqhZB13qYgGONW1cD3pPiCuimGv91tMKpR4GrFXGr/Y3HgwKjT0FTOGSPp
4x/m6vznVDqWgCQipGFYX7Y8+hhQ0SCZtIIY8DDboX4OQDPBoI78Yl+nPjZMnp3F
LPenBsvvoDe6896uUoMYH472ze1rpdnp9K1HU6/jakGLcJGbdtOOA2o/DqHQuLUJ
OtN6/zr/tVwM2bOvepa/uw3FyU6Foh1vfgBUedrTi6MWb+dN/A3MkSD87DoPCw==
-----END CERTIFICATE-----
'| sudo tee /etc/ssl/certs/ssl-cert-snakeoil.pem

echo '-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDcMijbR6JknWiA
LMBUN4B3q6YXUgWMrMTuKztKluST1I1vbolqGvhMH/X8CKNl/aYUsjZX+9AjHi/3
qKW9j3AsvOD+IT/rbNd8xHXEVZ/EbxQYVuc2xpgjg7r+naO63eOHZ5lWmbsKyimv
8mjZOBQaPJEsMaSxBAEF9XKYy5duIgAEaRAT4UgpfgmiCL4Pl0YCls6LMlKp8Pm2
9IPXygeRNXxKhITc4SYuUy/CejDtiSkom6CpCg7aFzpiDjppfyFpCAwjhtU4om6I
CezhJcWk79ZovyLKZDp6KPGSvFW2UVyw5vOFjr0RybIL15aunuq1qGqmFoshhjRK
HQ9w8lbNAgMBAAECggEARf4rvogmtpTSguu2tw5tZ5zITuFjojPI5WwYjL0qK1OF
IcahJ3krNAd0yYh1aBYYlLuRSqZgoskVtkOFa5wMrCvd2On4x3zxgldwl9gf0PD+
Ej6NgHvgIGnfJtA1G1Es4f2sYDq9mdBpL+R+L44D1dMq0kF1eE8thBdhNfCBUiAl
ZlK89TtXyhZnY3rNPYsRsfDGjifInjHHCpWzAU5DONWpCV7zWVY1+t6h+dKCSCwm
ER9EBy4YyExyGxK4QjGAS93c3j5lhPUreZljxSOMO6lyDcJ8QYIIm9cC5IaQ0uCM
Q27eDngcphgU22w4zAoMwekwvHyVyH3Xx9+LWsI6gQKBgQD8mRUREgF/3kxtVIwN
27ylT0zSMDcI6IIDQ5f/WiIzHHx/qbCDlyuk65WAitWeAXeSKy15MAcyPK4ZfDYp
5BJr0cpCfAllWtomDUP8avD19jgXeSanMDAQqk3c1eU0kXTAO2t/plqnXnveMJEX
Ht65uwbDy7qW+h9URd/rU6X6uwKBgQDfKVw2v+d8uYUn+nx7mjD0Gq5avxT2UKRh
EE3/SulyDvXqjRFkEhOx0A3xxJCRBXO5oPP9URIy2kx9nD+khB//KMNh4u1250kQ
dTVCRiQU5xP9LRUEZrXO/9X8BK/vrRpcT8p5zaDgPd0HhlJwtqWKGQjYVOMBEYhM
Fm89WhVwFwKBgQCDs2Uyg0rY2pTKpDxptVoEbvZE2PK46FFxVjrX3qzaLU4UWes4
kQcmc9Z9MOXz/hvT0ENjXlFCNjUoAIVVDh80rCtiwr07ZUU8dcouv6tm8ruIMZif
rxZAeisiqztYT0aqO9Duu1Ok1DSNQpFDlsrV19fNGlntAfh3vf7j+bcepQKBgAgR
9NW+Bt8JznjtpAbMQqzxMhDyDA4ESI2CC3AKA3suc1IyG8jkpnWtsnNlylyUN+Uk
nu4wOlpAbre0KNEIPif6D2bA0BmWr5u6wVxOMQvYd26WbMYl+Lkto01j1gDy35sq
/4V8HC8/zXhyMRUGZeIimaFJIJRvT+CAhzFOyqutAoGBANLi4I0ZEnx9pgJjhAR4
8fqb8tRPIok2h2g2Fv5M39KhBd3Z52VnVdj1OqrRwI51PkR5Er6XpV7I6sJtg10K
FwLktzdztVOAtiuMIrwqZlnobr/3YCmg5jB1USVZYyc1KkYtD779SNJleyF4ST3Q
dLug13mRf8zQ44BuW5OYhKdl
-----END PRIVATE KEY-----
'| sudo tee /etc/ssl/private/ssl-cert-snakeoil.key
cd /root
rm -f /etc/ocserv/ocserv.conf
/bin/cat <<"EOM" >/etc/ocserv/ocserv.conf
auth = "pam"
tcp-port = 1194
run-as-user = nobody
run-as-group = daemon
socket-file = /var/run/ocserv-socket
server-cert = /etc/ssl/certs/ssl-cert-snakeoil.pem
server-key = /etc/ssl/private/ssl-cert-snakeoil.key
isolate-workers = true
max-clients = 0
max-same-clients = 2
keepalive = 32400
dpd = 90
mobile-dpd = 1800
try-mtu-discovery = false
cert-user-oid = 0.9.2342.19200300.100.1.1
tls-priorities = "NORMAL:%SERVER_PRECEDENCE:%COMPAT:-VERS-SSL3.0"
auth-timeout = 240
min-reauth-time = 3
max-ban-score = 50
ban-reset-time = 300
cookie-timeout = 300
deny-roaming = false
rekey-time = 172800
rekey-method = ssl
use-utmp = false
use-occtl = true
pid-file = /var/run/ocserv.pid
device = vpns
predictable-ips = true
ipv4-network = 10.8.0.0
ipv4-netmask = 255.255.255.0
dns = 8.8.8.8
dns = 8.8.4.4
ping-leases = false
cisco-client-compat = true
dtls-legacy = true
EOM


sudo touch /etc/apt/sources.list.d/trusty_sources.list
echo "deb http://us.archive.ubuntu.com/ubuntu/ trusty main universe" | sudo tee --append /etc/apt/sources.list.d/trusty_sources.list > /dev/null
sudo apt update -y

sudo apt install -y squid3=3.3.8-1ubuntu6 squid=3.3.8-1ubuntu6 squid3-common=3.3.8-1ubuntu6
/bin/cat <<"EOM" >/etc/init.d/squid3
#! /bin/sh
#
# squid		Startup script for the SQUID HTTP proxy-cache.
#
# Version:	@(#)squid.rc  1.0  07-Jul-2006  luigi@debian.org
#
### BEGIN INIT INFO
# Provides:          squid
# Required-Start:    $network $remote_fs $syslog
# Required-Stop:     $network $remote_fs $syslog
# Should-Start:      $named
# Should-Stop:       $named
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: Squid HTTP Proxy version 3.x
### END INIT INFO

NAME=squid3
DESC="Squid HTTP Proxy"
DAEMON=/usr/sbin/squid3
PIDFILE=/var/run/$NAME.pid
CONFIG=/etc/squid3/squid.conf
SQUID_ARGS="-YC -f $CONFIG"

[ ! -f /etc/default/squid ] || . /etc/default/squid

. /lib/lsb/init-functions

PATH=/bin:/usr/bin:/sbin:/usr/sbin

[ -x $DAEMON ] || exit 0

ulimit -n 65535

find_cache_dir () {
	w=" 	" # space tab
        res=`$DAEMON -k parse -f $CONFIG 2>&1 |
		grep "Processing:" |
		sed s/.*Processing:\ // |
		sed -ne '
			s/^['"$w"']*'$1'['"$w"']\+[^'"$w"']\+['"$w"']\+\([^'"$w"']\+\).*$/\1/p;
			t end;
			d;
			:end q'`
        [ -n "$res" ] || res=$2
        echo "$res"
}

grepconf () {
	w=" 	" # space tab
        res=`$DAEMON -k parse -f $CONFIG 2>&1 |
		grep "Processing:" |
		sed s/.*Processing:\ // |
		sed -ne '
			s/^['"$w"']*'$1'['"$w"']\+\([^'"$w"']\+\).*$/\1/p;
			t end;
			d;
			:end q'`
	[ -n "$res" ] || res=$2
	echo "$res"
}

create_run_dir () {
	run_dir=/var/run/squid3
	usr=`grepconf cache_effective_user proxy`
	grp=`grepconf cache_effective_group proxy`

	if [ "$(dpkg-statoverride --list $run_dir)" = "" ] &&
	   [ ! -e $run_dir ] ; then
		mkdir -p $run_dir
	  	chown $usr:$grp $run_dir
		[ -x /sbin/restorecon ] && restorecon $run_dir
	fi
}

start () {
	cache_dir=`find_cache_dir cache_dir`
	cache_type=`grepconf cache_dir`
	run_dir=/var/run/squid3

	#
	# Create run dir (needed for several workers on SMP)
	#
	create_run_dir

	#
	# Create spool dirs if they don't exist.
	#
	if test -d "$cache_dir" -a ! -d "$cache_dir/00"
	then
		log_warning_msg "Creating $DESC cache structure"
		$DAEMON -z -f $CONFIG
		[ -x /sbin/restorecon ] && restorecon -R $cache_dir
	fi

	umask 027
	ulimit -n 65535
	cd $run_dir
	start-stop-daemon --quiet --start \
		--pidfile $PIDFILE \
		--exec $DAEMON -- $SQUID_ARGS < /dev/null
	return $?
}

stop () {
	PID=`cat $PIDFILE 2>/dev/null`
	start-stop-daemon --stop --quiet --pidfile $PIDFILE --exec $DAEMON
	#
	#	Now we have to wait until squid has _really_ stopped.
	#
	sleep 2
	if test -n "$PID" && kill -0 $PID 2>/dev/null
	then
		log_action_begin_msg " Waiting"
		cnt=0
		while kill -0 $PID 2>/dev/null
		do
			cnt=`expr $cnt + 1`
			if [ $cnt -gt 24 ]
			then
				log_action_end_msg 1
				return 1
			fi
			sleep 5
			log_action_cont_msg ""
		done
		log_action_end_msg 0
		return 0
	else
		return 0
	fi
}

cfg_pidfile=`grepconf pid_filename`
if test "${cfg_pidfile:-none}" != "none" -a "$cfg_pidfile" != "$PIDFILE"
then
	log_warning_msg "squid.conf pid_filename overrides init script"
	PIDFILE="$cfg_pidfile"
fi

case "$1" in
    start)
	res=`$DAEMON -k parse -f $CONFIG 2>&1 | grep -o "FATAL: .*"`
	if test -n "$res";
	then
		log_failure_msg "$res"
		exit 3
	else
		log_daemon_msg "Starting $DESC" "$NAME"
		if start ; then
			log_end_msg $?
		else
			log_end_msg $?
		fi
	fi
	;;
    stop)
	log_daemon_msg "Stopping $DESC" "$NAME"
	if stop ; then
		log_end_msg $?
	else
		log_end_msg $?
	fi
	;;
    reload|force-reload)
	res=`$DAEMON -k parse -f $CONFIG 2>&1 | grep -o "FATAL: .*"`
	if test -n "$res";
	then
		log_failure_msg "$res"
		exit 3
	else
		log_action_msg "Reloading $DESC configuration files"
	  	start-stop-daemon --stop --signal 1 \
			--pidfile $PIDFILE --quiet --exec $DAEMON
		log_action_end_msg 0
	fi
	;;
    restart)
	res=`$DAEMON -k parse -f $CONFIG 2>&1 | grep -o "FATAL: .*"`
	if test -n "$res";
	then
		log_failure_msg "$res"
		exit 3
	else
		log_daemon_msg "Restarting $DESC" "$NAME"
		stop
		if start ; then
			log_end_msg $?
		else
			log_end_msg $?
		fi
	fi
	;;
    status)
	status_of_proc -p $PIDFILE $DAEMON $NAME && exit 0 || exit 3
	;;
    *)
	echo "Usage: /etc/init.d/$NAME {start|stop|reload|force-reload|restart|status}"
	exit 3
	;;
esac

exit 0
EOM

sudo chmod +x /etc/init.d/squid3
sudo update-rc.d squid3 defaults

echo "http_port 8080
acl to_vpn dst `curl ipinfo.io/ip`
http_access allow to_vpn 
via off
forwarded_for off
request_header_access Allow allow all
request_header_access Authorization allow all
request_header_access WWW-Authenticate allow all
request_header_access Proxy-Authorization allow all
request_header_access Proxy-Authenticate allow all
request_header_access Cache-Control allow all
request_header_access Content-Encoding allow all
request_header_access Content-Length allow all
request_header_access Content-Type allow all
request_header_access Date allow all
request_header_access Expires allow all
request_header_access Host allow all
request_header_access If-Modified-Since allow all
request_header_access Last-Modified allow all
request_header_access Location allow all
request_header_access Pragma allow all
request_header_access Accept allow all
request_header_access Accept-Charset allow all
request_header_access Accept-Encoding allow all
request_header_access Accept-Language allow all
request_header_access Content-Language allow all
request_header_access Mime-Version allow all
request_header_access Retry-After allow all
request_header_access Title allow all
request_header_access Connection allow all
request_header_access Proxy-Connection allow all
request_header_access User-Agent allow all
request_header_access Cookie allow all
request_header_access All deny all 
http_access deny all"| sudo tee /etc/squid3/squid.conf

apt-get install stunnel4 -y
sed -i 's/ENABLED=0/ENABLED=1/g' /etc/default/stunnel4
/bin/cat <<"EOM" > /etc/stunnel/stunnel.pem
-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEAyN+jQb8vvS1jwbQSXAP9H0alRxuXuijhIp3u1gePGBsGLGg8
CWQrdhbB40W7Ov2xzg4KyiRwLgcfnOP2tHvtsN7BzC8DWrqqZsNyENDyIs3sX5oc
+JGLQZJiv2QSAP3N/4/UAAswUnGRW1TzQFXISSVeiScBsB96LoVLiPdA1e4Hhjkb
vggLOHHTcXqc1BBzIt9eg672O+yiILsOFuYPGh3TBwVZ0DvKYZocEsJ/RExOuAID
x0+THlpyO3PZhIo3EN5BVCmBcsUboByH9/Lsh+15tJqpvM8uiB9pjxlWUiRNiHjm
J5+pOWX4FpGlgrJUYSSsUUddXmPVWAj1BeQ2GwIDAQABAoIBAH7ISC5zERqBz3iu
wve4vMZEvISI8dbZfl9u9xO3aaV5SQg2Mc5rntLFwlJD7Mxq2xKG4mB7ZyJl9Jn9
d/SqU3dS4VaSRbe6IVsC+LeMaYd2GT6t8qMgmZglYJYT/xkJGD+488GjTjh63Zeb
onx0qBkisOw35mTXOTKrhuVHyXA70dD1an0fXi6tiNkIT4AVwLgqJuFxE0seePlN
Y35jZF4JvX8hOvkSshkzxNWSIs2LOOCJL7dH90FYvUYA/kvW+64O7pouA/p/VkYD
rO0fYgJmureiUZfwEVJKfnBgdhIbStA3lRxDzDmxr1BBVFaraSZ+12/jQVEXOaRb
ErovK6ECgYEA5nV12egMRn3l3MItWmcURIDtTU8cy3WreP2zTzx9RZDs3Rw2HEbR
0jyLzJOHfyFdyGrZtbUAa/LoOKT2YvPKQ2P4k4ZFbYcnl7cgAL28CrpZgNZXoEaL
sMf6Qp6PG+VUSFoFcOi/GM2c4ZypVOR5MwGbfpJ4fusekxQiTijWs4cCgYEA3yLK
Kt8bXHgg7B92mTFEKsiYrgk5SgPcYQ/HxYOMS3hrI8J3JWkMOWCCAbS1nSPPd0BY
jXGL/LSRmWA8bX/objwq8Q8YDTuuDCIPsh/SoFZsdHWc0ZlOv1BsWGijJGa21n64
Ja5r3LWSH6YLCy2PmoQzBDaCtmr/rZWXPaS4tc0CgYEAre9jJjab5SwqK6amQj/g
LR+9eobGLc0+wM+B4MC/r5yFGRCsykStIeaugJWsQ0g0lwoGDL1ydwbbO71NdDuZ
oak3OGizx8mlGT2OOuD4poQk/zdG5WG5FpCoElXHnv9D0GOZDbGsYRT2XdU2fCsA
Sn3hFPOJXAkqh0k/5wutl8sCgYEA2aXAluK6eI7AZjEmaLTSbfzuWEus8tIjQxW2
YaU30mGp9952gyoc/1ZwWSOgRp+ofQRpm8XWqu6iWn2xU4mA+Q19QVbcugOteC49
Kxy5QSYrcclK5nNoiVnz5KRkBVyfGUfPbQneMhF1b6NxgDy3pxst+/0DsNVbgUC5
niou9T0CgYEAkTXYooaf7JTAMlu/wLunkT0ZWKL/bU4ZgOFVFnF2gdfWJnHTMSu5
PtxyjisZJNbON6xW0pIjcTuUQCIpL0LoZ7qd5zi5QqISb+eKzK8ENMxgnV7MEx78
lufFKJYrjhC8j9pwY5pAR5uw2HKMS34IqLXct6NypoEYsJ48YDfA0Qw=
-----END RSA PRIVATE KEY-----
-----BEGIN CERTIFICATE-----
MIIEATCCAumgAwIBAgIJAPDuiksIWVs2MA0GCSqGSIb3DQEBCwUAMIGWMQswCQYD
VQQGEwJQSDESMBAGA1UECAwJU1RST05HVlBOMRIwEAYDVQQHDAlTVFJPTkdWUE4x
EjAQBgNVBAoMCVNUUk9OR1ZQTjESMBAGA1UECwwJU1RST05HVlBOMRIwEAYDVQQD
DAlTVFJPTkdWUE4xIzAhBgkqhkiG9w0BCQEWFHN0cm9uZy12cG5AZ21haWwuY29t
MB4XDTE4MDcwMzA1MTM0MVoXDTIxMDcwMjA1MTM0MVowgZYxCzAJBgNVBAYTAlBI
MRIwEAYDVQQIDAlTVFJPTkdWUE4xEjAQBgNVBAcMCVNUUk9OR1ZQTjESMBAGA1UE
CgwJU1RST05HVlBOMRIwEAYDVQQLDAlTVFJPTkdWUE4xEjAQBgNVBAMMCVNUUk9O
R1ZQTjEjMCEGCSqGSIb3DQEJARYUc3Ryb25nLXZwbkBnbWFpbC5jb20wggEiMA0G
CSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDI36NBvy+9LWPBtBJcA/0fRqVHG5e6
KOEine7WB48YGwYsaDwJZCt2FsHjRbs6/bHODgrKJHAuBx+c4/a0e+2w3sHMLwNa
uqpmw3IQ0PIizexfmhz4kYtBkmK/ZBIA/c3/j9QACzBScZFbVPNAVchJJV6JJwGw
H3ouhUuI90DV7geGORu+CAs4cdNxepzUEHMi316DrvY77KIguw4W5g8aHdMHBVnQ
O8phmhwSwn9ETE64AgPHT5MeWnI7c9mEijcQ3kFUKYFyxRugHIf38uyH7Xm0mqm8
zy6IH2mPGVZSJE2IeOYnn6k5ZfgWkaWCslRhJKxRR11eY9VYCPUF5DYbAgMBAAGj
UDBOMB0GA1UdDgQWBBTxI2YSnxnuDpwgxKOUgglmgiH/vDAfBgNVHSMEGDAWgBTx
I2YSnxnuDpwgxKOUgglmgiH/vDAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBCwUA
A4IBAQC30dcIPWlFfBEK/vNzG1Dx+BWkHCfd2GfmVc+VYSpmiTox13jKBOyEdQs4
xxB7HiESKkpAjQ0YC3mjE6F53NjK0VqdfzXhopg9i/pQJiaX0KTTcWIelsJNg2aM
s8GZ0nWSytcAqAV6oCnn+eOT/IqnO4ihgmaVIyhfYvRgXfPU/TuERtL9f8pAII44
jAVcy60MBZ1bCwQZcToZlfWCpO/8nLg4nnv4e3W9UeC6rDgWgpI6IXS3jikN/x3P
9JIVFcWLtsOLC+D/33jSV8XDM3qTTRv4i/M+mva6znOI89KcBjsEhX5AunSQZ4Zg
QkQTJi/td+5kVi00NXxlHYH5ztS1
-----END CERTIFICATE-----
EOM

echo 'cert=/etc/stunnel/stunnel.pem
socket = a:SO_REUSEADDR=1
socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1
client = no

[ocserv]
accept = 443
connect = 127.0.0.1:1194'| sudo tee /etc/stunnel/stunnel.conf





sudo add-apt-repository ppa:linrunner/tlp -y
sudo apt-get update -y
sudo apt-get install tlp tlp-rdw -y
sudo tlp start

echo 'fs.file-max = 51200
net.core.rmem_max = 67108864
net.core.wmem_max = 67108864
net.core.netdev_max_backlog = 250000
net.core.somaxconn = 4096
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 30
net.ipv4.tcp_keepalive_time = 1200
net.ipv4.ip_local_port_range = 10000 65000
net.ipv4.tcp_max_syn_backlog = 8192
net.ipv4.tcp_max_tw_buckets = 5000
net.ipv4.tcp_mem = 25600 51200 102400
net.ipv4.tcp_rmem = 4096 87380 67108864
net.ipv4.tcp_wmem = 4096 65536 67108864
net.ipv4.tcp_mtu_probing = 1
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
net.ipv4.ip_forward=1
net.ipv4.icmp_echo_ignore_all = 1' >> /etc/sysctl.conf
echo '* soft nofile 512000
* hard nofile 512000' >> /etc/security/limits.conf
ulimit -n 512000
SELINUX=disabled 
sysctl -p

iptables -F; iptables -X; iptables -Z
iptables -t nat -A POSTROUTING -s 10.8.0.0/16 -o eth0 -j MASQUERADE
iptables -t nat -A POSTROUTING -s 10.8.0.0/16 -o eth0 -j SNAT --to-source `curl ipecho.net/plain`
iptables -t nat -A POSTROUTING -s 10.8.0.0/16 -o ens3 -j MASQUERADE
iptables -t nat -A POSTROUTING -s 10.8.0.0/16 -o ens3 -j SNAT --to-source `curl ipecho.net/plain`

sudo usermod -a -G www-data root
sudo chgrp -R www-data /var/www
sudo chmod -R g+w /var/www

sudo timedatectl set-timezone Asia/Manila
timedatectl

sudo apt install debconf-utils -y

echo iptables-persistent iptables-persistent/autosave_v4 boolean true | sudo debconf-set-selections
echo iptables-persistent iptables-persistent/autosave_v6 boolean true | sudo debconf-set-selections
sudo apt-get install iptables-persistent -y

iptables-save > /etc/iptables/rules.v4 
ip6tables-save > /etc/iptables/rules.v6

apt-get install php php-mysqli php-mysql php-gd php-mbstring python -y
apt-get install netcat lsof php php-mysqli php-mysql php-gd php-mbstring python -y

cat << \socksopenvpn > /usr/local/sbin/proxy.py
#!/usr/bin/env python3
# encoding: utf-8
# SocksProxy By: Ykcir Ogotip Caayon
import socket, threading, thread, select, signal, sys, time
from os import system
system("clear")
#conexao
IP = '0.0.0.0'
try:
   PORT = int(sys.argv[1])
except:
   PORT = 8000
PASS = ''
BUFLEN = 8196 * 8
TIMEOUT = 60
MSG = 'SaudiConnect'
DEFAULT_HOST = '0.0.0.0:1194'
RESPONSE = "HTTP/1.1 200 " + str(MSG) + "\r\n\r\n"

class Server(threading.Thread):
    def __init__(self, host, port):
        threading.Thread.__init__(self)
        self.running = False
        self.host = host
        self.port = port
        self.threads = []
	self.threadsLock = threading.Lock()
	self.logLock = threading.Lock()

    def run(self):
        self.soc = socket.socket(socket.AF_INET)
        self.soc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.soc.settimeout(2)
        self.soc.bind((self.host, self.port))
        self.soc.listen(0)
        self.running = True

        try:                    
            while self.running:
                try:
                    c, addr = self.soc.accept()
                    c.setblocking(1)
                except socket.timeout:
                    continue
                
                conn = ConnectionHandler(c, self, addr)
                conn.start();
                self.addConn(conn)
        finally:
            self.running = False
            self.soc.close()
            
    def printLog(self, log):
        self.logLock.acquire()
        print log
        self.logLock.release()
	
    def addConn(self, conn):
        try:
            self.threadsLock.acquire()
            if self.running:
                self.threads.append(conn)
        finally:
            self.threadsLock.release()
                    
    def removeConn(self, conn):
        try:
            self.threadsLock.acquire()
            self.threads.remove(conn)
        finally:
            self.threadsLock.release()
                
    def close(self):
        try:
            self.running = False
            self.threadsLock.acquire()
            
            threads = list(self.threads)
            for c in threads:
                c.close()
        finally:
            self.threadsLock.release()
			

class ConnectionHandler(threading.Thread):
    def __init__(self, socClient, server, addr):
        threading.Thread.__init__(self)
        self.clientClosed = False
        self.targetClosed = True
        self.client = socClient
        self.client_buffer = ''
        self.server = server
        self.log = 'Conexao: ' + str(addr)

    def close(self):
        try:
            if not self.clientClosed:
                self.client.shutdown(socket.SHUT_RDWR)
                self.client.close()
        except:
            pass
        finally:
            self.clientClosed = True
            
        try:
            if not self.targetClosed:
                self.target.shutdown(socket.SHUT_RDWR)
                self.target.close()
        except:
            pass
        finally:
            self.targetClosed = True

    def run(self):
        try:
            self.client_buffer = self.client.recv(BUFLEN)
        
            hostPort = self.findHeader(self.client_buffer, 'X-Real-Host')
            
            if hostPort == '':
                hostPort = DEFAULT_HOST

            split = self.findHeader(self.client_buffer, 'X-Split')

            if split != '':
                self.client.recv(BUFLEN)
            
            if hostPort != '':
                passwd = self.findHeader(self.client_buffer, 'X-Pass')
				
                if len(PASS) != 0 and passwd == PASS:
                    self.method_CONNECT(hostPort)
                elif len(PASS) != 0 and passwd != PASS:
                    self.client.send('HTTP/1.1 400 WrongPass!\r\n\r\n')
                if hostPort.startswith(IP):
                    self.method_CONNECT(hostPort)
                else:
                   self.client.send('HTTP/1.1 403 Forbidden!\r\n\r\n')
            else:
                print '- No X-Real-Host!'
                self.client.send('HTTP/1.1 400 NoXRealHost!\r\n\r\n')

        except Exception as e:
            self.log += ' - error: ' + e.strerror
            self.server.printLog(self.log)
	    pass
        finally:
            self.close()
            self.server.removeConn(self)

    def findHeader(self, head, header):
        aux = head.find(header + ': ')
    
        if aux == -1:
            return ''

        aux = head.find(':', aux)
        head = head[aux+2:]
        aux = head.find('\r\n')

        if aux == -1:
            return ''

        return head[:aux];

    def connect_target(self, host):
        i = host.find(':')
        if i != -1:
            port = int(host[i+1:])
            host = host[:i]
        else:
            if self.method=='CONNECT':
                port = 1194
            else:
                port = 22

        (soc_family, soc_type, proto, _, address) = socket.getaddrinfo(host, port)[0]

        self.target = socket.socket(soc_family, soc_type, proto)
        self.targetClosed = False
        self.target.connect(address)

    def method_CONNECT(self, path):
    	self.log += ' - CONNECT ' + path
        self.connect_target(path)
        self.client.sendall(RESPONSE)
        self.client_buffer = ''
        self.server.printLog(self.log)
        self.doCONNECT()
                    
    def doCONNECT(self):
        socs = [self.client, self.target]
        count = 0
        error = False
        while True:
            count += 1
            (recv, _, err) = select.select(socs, [], socs, 3)
            if err:
                error = True
            if recv:
                for in_ in recv:
		    try:
                        data = in_.recv(BUFLEN)
                        if data:
			    if in_ is self.target:
				self.client.send(data)
                            else:
                                while data:
                                    byte = self.target.send(data)
                                    data = data[byte:]

                            count = 0
			else:
			    break
		    except:
                        error = True
                        break
            if count == TIMEOUT:
                error = True

            if error:
                break



def main(host=IP, port=PORT):
    print "\033[0;34mâ”"*8,"\033[1;32m PROXY SOCKS","\033[0;34mâ”"*8,"\n"
    print "\033[1;33mIP:\033[1;32m " + IP
    print "\033[1;33mPORTA:\033[1;32m " + str(PORT) + "\n"
    print "\033[0;34mâ”"*10,"\033[1;32m StrongHold","\033[0;34mâ”\033[1;37m"*11,"\n"
    server = Server(IP, PORT)
    server.start()
    while True:
        try:
            time.sleep(2)
        except KeyboardInterrupt:
            print '\nClosing...'
            server.close()
            break
if __name__ == '__main__':
    main()
socksopenvpn


cat << \autostart > /root/auto
#!/bin/bash
if nc -z localhost 80; then
    echo "SocksProxy running"
else
    echo "Starting Port 80
    screen -dmS proxy2 python /usr/local/sbin/proxy.py 80
fi
autostart

chmod +x /root/auto
/root/auto;
crontab -r
echo "SHELL=/bin/bash
* * * * * /bin/bash /root/auto >/dev/null 2>&1
*/3 * * * * /bin/bash /root/ssh.sh >/dev/null 2>&1" | crontab -

echo "php /root/sshcon.php
/bin/bash /root/active.sh
/bin/bash /root/inactive.sh" > /root/ssh.sh

update-rc.d squid3 enable
update-rc.d ocserv enable
update-rc.d apache2 enable
update-rc.d cron enable
update-rc.d stunnel4 enable
update-rc.d tlp enable
service ocserv restart
service squid3 start
service apache2 start
service stunnel4 restart
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
sed -i 's/#ForwardToWall=yes/ForwardToWall=no/g' /etc/systemd/journald.conf
clear
echo "Installation Done"
sudo apt-get clean
history -c
cd /root || exit
rm -f /root/installer.sh
echo -e "\e[1;32m Installing Done \033[0m"
echo 'root:@@F1r3n3ts' | sudo chpasswd
reboot
