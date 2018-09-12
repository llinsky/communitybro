signature dpd_bittorrent {
	ip-proto == tcp
	payload /\x13BitTorrent protocol.\x00.\x00\x00/
	enable "BitTorrent"
 }
