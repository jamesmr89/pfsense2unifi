##A perl script to convert a pfSense config file to the necessary Unifi CLI commands to port the OpenVPN server configuration over

#Note this is highly untested, as in, it has been tested once so far with a single pfsense config file.   This was created as a bandaid until Ubiquity supports this feature in the controller UI.

###Usage:
##To generate the Unifi Configuration
+perl pfsense2unifi.pl --file <pfsense_xml> > vpn.sh
+scp vpn.sh admin@unifi_ip:/tmp/vpn.sh
+ssh into unifi and run the following:
+configure
+source /tmp/vpn.sh
+commit
+save

###To add another user (Must do above first): 
+perl pfsense2unifi.pl --file <pfsense_xml> --user <username>
