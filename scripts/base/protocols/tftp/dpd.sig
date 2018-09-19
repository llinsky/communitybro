
signature dpd_tftp {
	
	ip-proto == udp
	
	dst-port == 69
	src-port >= 1024

	enable "tftp"
}