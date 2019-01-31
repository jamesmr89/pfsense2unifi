#!/usr/bin/perl

# use module
use Data::Dumper;
use Getopt::Long;
use JSON;
use MIME::Base64;
use Net::Netmask;
use XML::Simple;

# Read command-line arguments, exit with usage message in case of error
GetOptions( 'file=s' => \$pfSenseConfig, 'user=s' => \$user, 'vpnid=i' => \$vpnid )
    or usage(); 

if (not defined $pfSenseConfig) {
    # print specific message, the generic usage message, and exit
    say STDERR "Argument 'file' is mandatory";
    #usage();
}

# create object
$xml = new XML::Simple;

# read XML file
$data = $xml->XMLin($pfSenseConfig, ForceArray=>['openvpn-server']);

foreach $server (@{$data->{'openvpn'}->{'openvpn-server'}}) {

foreach $server (@{$data->{'openvpn'}->{'openvpn-server'}}) {

# determine path for output files
my $path = $server->{'description'};
$path =~ s/ /_/g;

# Get CA Cert Key
my $caref = $server->{caref};
my $servercacert;
my $servercakey;
foreach my $ca (keys $data->{ca}) {
  if ($data->{ca}[$ca]->{refid} eq $caref) {
    $servercacert = decode_base64($data->{ca}[$ca]->{crt}); 
    $servercakey = decode_base64($data->{ca}[$ca]->{prv}); 
  }
}

# Get Server Cert and Key
my $certref = $server->{certref};
my $servercert;
my $serverkey;
foreach my $cert (keys $data->{cert}) {
  if ($data->{cert}[$cert]->{type} eq 'server' && $server->{certref} eq $certref) {
    
    $servercert = decode_base64($data->{cert}[$cert]->{crt});
    $serverkey = decode_base64($data->{cert}[$cert]->{prv});
  }
}

# TLS Auth Key 
my $tlskey = decode_base64($server->{tls});
$tlskey =~ s/\r//g;
# DH Key 
#my $dhcmd = "openssl dhparam $server->{'dh_length'} 2>/dev/null";
#my $dhkey = `$dhcmd`;

`mkdir -p $path`;
# Unifi Config
open(my $fh, '>', "$path/vpn.sh");
print $fh "mkdir -p /config/auth/keys\n";
print $fh "### CA Certificate ###\n";
print $fh "echo '$servercacert' > /config/auth/keys/ca.crt\n\n";
print $fh "### Server Certificate ###\n";
print $fh "echo '$servercert' > /config/auth/keys/server.crt\n\n";
print $fh "### Server Key ###\n";
print $fh "echo '$serverkey' > /config/auth/keys/server.key\n\n";
print $fh "### TLS Key ###\n";
print $fh "echo '$tlskey' > /config/auth/keys/tls-auth\n\n";
print $fh "### DH Key ###\n";
print $fh "echo '$dhkey' > /config/auth/keys/dh.pem\n";
close $fh;

%firewall_rule = (
	'action'=> 'accept',
	'description'=> 'Allow OpenVPN clients in',
	'log'=> 'disable',
	'protocol'=> 'udp',
	'destination'=> {'port'=>$server->{'local_port'}}
);

@openvpn_options = (
"--auth $server->{'digest'}",
"--tls-auth /config/auth/keys/tls-auth 0",
"--cipher $server->{'crypto'}",
"--proto $server->{'protocol'}",
"--port $server->{'local_port'}",
"--push route $server->{'local_network'}"
);

if ($server->{'dns_domain'}) {
  push @openvpn_options, "-- push dhcp-option DOMAIN $server->{'dns_domain'}";
}
if ($server->{'dns_server1'}) {
  push @openvpn_options, "-- push dhcp-option DNS $server->{'dns_server1'}";
}
if ($server->{'dns_server2'}) {
  push @openvpn_options, "-- push dhcp-option DNS $server->{'dns_server2'}";
}

%openvpn_config = (
	'mode'=> 'server',
	'server'=> {
		'subnet'=> $server->{'local_network'}
	},
	'openvpn-option'=> \@openvpn_options,
	'tls'=> {
		"ca-cert-file" => "/config/auth/keys/ca.crt",
		"cert-file" => "/config/auth/keys/server.crt",
		"dh-file" => "/config/auth/keys/dh.pem",
		"key-file" => "/config/auth/keys/server.key"
	}
);

my %config_gateway;
$config_gateway{"firewall"}{"name"}{"WAN_LOCAL"}{"rule"}{20} = \%firewall_rule;
$config_gateway{"interfaces"}{"openvpn"}{"vtun0"} = \%openvpn_config;

$json = JSON->new->allow_nonref;
$pretty_printed = $json->pretty->encode( \%config_gateway );
open my $fh, ">", "$path/config.gateway.json";
print $fh $pretty_printed;
close $fh;

}
