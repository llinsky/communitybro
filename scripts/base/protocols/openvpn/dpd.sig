signature dpd_openvpn_udp {
	ip-proto == udp
	dst-port == 1194
	enable "openvpn_udp"
}

signature dpd_openvpn_tcp {
	ip-proto == tcp
	dst-port == 1194
	enable "openvpn_tcp"
}