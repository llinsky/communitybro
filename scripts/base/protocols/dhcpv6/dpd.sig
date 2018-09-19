signature dpd_dhcvp6_client {
  ip-proto == udp
  src-port == 546
  dst-port == 547
  enable "dhcpv6"
}

signature dpd_dhcvp6_server {
  ip-proto == udp
  src-port == 547
  dst-port == 546
  enable "dhcpv6"
}
