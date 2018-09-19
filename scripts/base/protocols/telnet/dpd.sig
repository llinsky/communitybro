signature dpd_telnet {
	ip-proto == tcp
	dst-port == 23
	enable "telnet"
}
