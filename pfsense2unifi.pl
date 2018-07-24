#!/usr/bin/perl

# use module
use Data::Dumper;
use Getopt::Long;
use JSON;
use MIME::Base64;
use Net::Netmask;
use XML::Simple;

# Read command-line arguments, exit with usage message in case of error
GetOptions( 'file=s' => \$pfSenseConfig, 'user=s' => \$user )
    or usage(); 

if (not defined $pfSenseConfig) {
    # print specific message, the generic usage message, and exit
    say STDERR "Argument 'file' is mandatory";
    #usage();
}

# create object
$xml = new XML::Simple;

# read XML file
$data = $xml->XMLin($pfSenseConfig);

# determine path for output files
my $path = 'openvpnconfigs/'.$data->{openvpn}->{'openvpn-server'}->{'description'}.'/pki';
$path =~ s/ /_/g;


if (!$user) {
	# Get CA Cert Key
	my $caref = $data->{openvpn}->{'openvpn-server'}->{caref};
	my $servercacert;
	my $servercakey;
	foreach my $ca (keys $data->{ca}) {
	  if ($data->{ca}[$ca]->{refid} eq $caref) {
	    $servercacert = decode_base64($data->{ca}[$ca]->{crt}); 
	    $servercakey = decode_base64($data->{ca}[$ca]->{prv}); 
	  }
	}

	# Get Server Cert and Key
	my $certref = $data->{openvpn}->{'openvpn-server'}->{certref};
	my $servercert;
	my $serverkey;
	foreach my $cert (keys $data->{cert}) {
	  if ($data->{cert}[$cert]->{type} eq 'server' && $data->{openvpn}->{'openvpn-server'}->{certref} eq $certref) {
	    $servercert = decode_base64($data->{cert}[$cert]->{crt});
	    $serverkey = decode_base64($data->{cert}[$cert]->{prv});
	  }
	}

	# TLS Auth Key 
	my $tlskey = decode_base64($data->{openvpn}->{'openvpn-server'}->{tls});
	$tlskey =~ s/\r//g;

	# DH Key 
	my $dhcmd = "openssl dhparam $data->{openvpn}->{'openvpn-server'}->{'dh_length'} 2>/dev/null";
	my $dhkey = `$dhcmd`;

my $config = <<"END_CONFIG";
set interfaces openvpn vtun0 mode server
set interfaces openvpn vtun0 server subnet $data->{openvpn}->{'openvpn-server'}->{'tunnel_network'} 
set interfaces openvpn vtun0 tls ca-cert-file /config/auth/keys/ca.crt
set interfaces openvpn vtun0 tls cert-file /config/auth/keys/server.crt
set interfaces openvpn vtun0 tls key-file /config/auth/keys/server.key
set interfaces openvpn vtun0 tls dh-file /config/auth/keys/dh.pem
set interfaces openvpn vtun0 openvpn-option ' - auth $data->{openvpn}->{'openvpn-server'}->{'digest'}'
set interfaces openvpn vtun0 openvpn-option ' - tls-auth /config/auth/keys/tls-auth 0'
set interfaces openvpn vtun0 openvpn-option ' - cipher $data->{openvpn}->{'openvpn-server'}->{'crypto'}'
set interfaces openvpn vtun0 openvpn-option ' - proto $data->{openvpn}->{'openvpn-server'}->{'protocol'}'
set interfaces openvpn vtun0 openvpn-option ' - push redirect-gateway def1'
set interfaces openvpn vtun0 openvpn-option ' - port $data->{openvpn}->{'openvpn-server'}->{'local_port'}'
END_CONFIG

	if ($data->{openvpn}->{'openvpn-server'}->{'dns_domain'}) {
	  $config .= "set interfaces openvpn vtun0 openvpn-option ' - push dhcp-option DOMAIN $data->{openvpn}->{'openvpn-server'}->{'dns_domain'}'\n";
	}
	if ($data->{openvpn}->{'openvpn-server'}->{'dns_server1'}) {
	  $config .= "set interfaces openvpn vtun0 openvpn-option ' - push dhcp-option DNS $data->{openvpn}->{'openvpn-server'}->{'dns_server1'}'\n";
	}
	if ($data->{openvpn}->{'openvpn-server'}->{'dns_server2'}) {
	  $config .= "set interfaces openvpn vtun0 openvpn-option ' - push dhcp-option DNS $data->{openvpn}->{'openvpn-server'}->{'dns_server2'}'\n";
	}

my $fw_config = <<"FW_CONFIG";
set firewall name WAN_LOCAL rule 20 action accept
set firewall name WAN_LOCAL rule 20 description “Allow OpenVPN clients in”
set firewall name WAN_LOCAL rule 20 destination port $data->{openvpn}->{'openvpn-server'}->{'local_port'} 
set firewall name WAN_LOCAL rule 20 log disable
set firewall name WAN_LOCAL rule 20 protocol udp
FW_CONFIG

	my $cidr = $data->{openvpn}->{'openvpn-server'}->{'local_network'};
	my $block = Net::Netmask->new2( $cidr ) or die $Net::Netmask::error;
	$config .= 'set interfaces openvpn vtun0 openvpn-option “ — push route '.$block->base.' '.$block->mask.'”'."\n";

	# Unifi Config
	print "mkdir -p /config/auth/keys\n";
	print "### CA Certificate ###\n";
	print "echo '$servercacert' > /config/auth/keys/ca.crt\n\n";
	print "### Server Certificate ###\n";
	print "echo '$servercert' > /config/auth/keys/server.crt\n\n";
	print "### Server Key ###\n";
	print "echo '$serverkey' > /config/auth/keys/server.key\n\n";
	print "### TLS Key ###\n";
	print "echo '$tlskey' > /config/auth/keys/tls-auth\n\n";
	print "### DH Key ###\n";
	print "echo '$dhkey' > /config/auth/keys/dh.pem\n";
	print "\n$config";
	print $fw_config;

	# openvpn-generate config 
	`mkdir -p $path/clientconfigs`;
	### CA Certificate ###
	open(my $fh, '>', $path.'/ca.crt');
	print $fh $servercacert;
	close $fh;
	### CA Key ###
	open(my $fh, '>', $path.'/ca.key');
	print $fh $servercakey;
	close $fh;
	### TLS Key ###
	open(my $fh, '>', $path.'/ta.key');
	print $fh $tlskey;
	close $fh;

} else {
	$cainfo = `openssl x509 -noout -subject -in $path/ca.crt`;
	chomp $cainfo;
	my %ca_info_hash = split /[\/=]/, $cainfo;

	`openssl genrsa -out $path/clientconfigs/$user.key 2048 2>/dev/null`;
	`openssl req -new -key $path/clientconfigs/$user.key -out $path/clientconfigs/$user.csr -subj "/C=$ca_info_hash{C}/ST=$ca_info_hash{ST}/L=$ca_info_hash{L}/O=$ca_info_hash{O}/CN=$user" 2>/dev/null`;
	`openssl x509 -req -in $path/clientconfigs/$user.csr -CA $path/ca.crt -CAkey $path/ca.key -CAcreateserial -out $path/clientconfigs/$user.crt -days 1024 -sha256 2>/dev/null`;
	`rm $path/clientconfigs/$user.csr`;

	my $ca_cert = `cat $path/ca.crt`;
	my $client_cert = `cat $path/clientconfigs/$user.crt`;
	my $client_key = `cat $path/clientconfigs/$user.key`;
	my $tlskey = `cat $path/ta.key`;

my $client_config = <<"CLIENT_CONFIG";
#-- Config Auto Generated By pfSense for Viscosity --#

#viscosity startonopen false
#viscosity dhcp true
#viscosity dnssupport true
#viscosity name
dev tun
persist-tun
persist-key
cipher AES-128-CBC
auth SHA1
tls-client
client
resolv-retry infinite
remote 50.245.139.57 1195 udp
lport 0
verify-x509-name "Azose Commercial VPN Server" name
ns-cert-type server

<ca>
$ca_cert
</ca>
<cert>
$client_cert
</cert>
<key>
$client_key
</key>
<tls-auth>
$tlskey
</tls-auth>
 key-direction 1
CLIENT_CONFIG

	open(my $fh, '>', $path.'/clientconfigs/'.$user.'.ovpn');
	print $fh $client_config;
	close $fh;
}
