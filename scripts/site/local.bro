##! Local site policy. Customize as appropriate.
##!
##! This file will not be overwritten when upgrading or reinstalling!

# This script logs which scripts were loaded during each run.
@load policy/misc/loaded-scripts

# Apply the default tuning scripts for common tuning settings.
@load policy/tuning/defaults

# Estimate and log capture loss.
@load policy/misc/capture-loss

# Enable logging of memory, packet and lag statistics.
@load policy/misc/stats

# Load the scan detection script.
@load policy/misc/scan

# Detect traceroute being run on the network. This could possibly cause
# performance trouble when there are a lot of traceroutes on your network.
# Enable cautiously.
#@load policy/misc/detect-traceroute

# Generate notices when vulnerable versions of software are discovered.
# The default is to only monitor software found in the address space defined
# as "local".  Refer to the software framework's documentation for more
# information.
@load policy/frameworks/software/vulnerable

# Detect software changing (e.g. attacker installing hacked SSHD).
@load policy/frameworks/software/version-changes

# This adds signatures to detect cleartext forward and reverse windows shells.
@load-sigs policy/frameworks/signatures/detect-windows-shells

# Load all of the scripts that detect software in various protocols.
@load policy/protocols/ftp/software
@load policy/protocols/smtp/software
@load policy/protocols/ssh/software
@load policy/protocols/http/software
# The detect-webapps script could possibly cause performance trouble when
# running on live traffic.  Enable it cautiously.
#@load protocols/http/detect-webapps

# This script detects DNS results pointing toward your Site::local_nets
# where the name is not part of your local DNS zone and is being hosted
# externally.  Requires that the Site::local_zones variable is defined.
@load policy/protocols/dns/detect-external-names

# Script to detect various activity in FTP sessions.
@load policy/protocols/ftp/detect

# Scripts that do asset tracking.
@load policy/protocols/conn/known-hosts
@load policy/protocols/conn/known-services
@load policy/protocols/ssl/known-certs

# This script enables SSL/TLS certificate validation.
@load policy/protocols/ssl/validate-certs

# This script prevents the logging of SSL CA certificates in x509.log
@load policy/protocols/ssl/log-hostcerts-only

# Uncomment the following line to check each SSL certificate hash against the ICSI
# certificate notary service; see http://notary.icsi.berkeley.edu .
# @load protocols/ssl/notary

# If you have libGeoIP support built in, do some geographic detections and
# logging for SSH traffic.
@load policy/protocols/ssh/geo-data
# Detect hosts doing SSH bruteforce attacks.
@load policy/protocols/ssh/detect-bruteforcing
# Detect logins using "interesting" hostnames.
@load policy/protocols/ssh/interesting-hostnames

# Detect SQL injection attacks.
@load policy/protocols/http/detect-sqli

#### Network File Handling ####

# Enable MD5 and SHA1 hashing for all files.
@load policy/frameworks/files/hash-all-files

# Detect SHA1 sums in Team Cymru's Malware Hash Registry.
@load policy/frameworks/files/detect-MHR

# Uncomment the following line to enable detection of the heartbleed attack. Enabling
# this might impact performance a bit.
# @load policy/protocols/ssl/heartbleed

# Uncomment the following line to enable logging of connection VLANs. Enabling
# this adds two VLAN fields to the conn.log file.
# @load policy/protocols/conn/vlan-logging

# Uncomment the following line to enable logging of link-layer addresses. Enabling
# this adds the link-layer address for each connection endpoint to the conn.log file.
# @load policy/protocols/conn/mac-logging

