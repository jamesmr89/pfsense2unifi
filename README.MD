# A perl script to convert a pfSense config file to the necessary Unifi CLI commands to port the OpenVPN server configuration over


*Note this is highly untested, as in, it has been tested once so far with a single pfsense config file.   This was created as a bandaid until Ubiquity supports this feature in the controller UI.*

#### Usage:
##### To generate the Unifi Configuration
+ perl pfsense2unifi.pl --file <pfsense_xml> --vpnid <pfsense_vpnid>
+ cd <folder created from above>
+ scp vpn.sh admin@unifi_ip:/tmp/vpn.sh
+ ssh into unifi and run the following:
+ sudo sh /tmp/vpn.sh

Add the created config.gateway.json to the /data/sites folder on the controller

Force a provision on the gateway from the controller.

You can add users via certs on the pfsense box, and use the client export tool for client configs.

I've been using this setup and have a few OpenVpn servers configured on pfSense all on different ports that are used to generate the configs for multiple USG's (I disable the servers after configuration)
