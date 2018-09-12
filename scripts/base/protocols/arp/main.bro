##
# Aaron Eppert
# PacketSled - 2015
##

#
# Abbreviations are taken from RFC 826:
#
# SHA: source hardware address
# SPA: source protocol address
# THA: target hardware address
# TPA: target protocol address
#

module ARP;

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		## Timestamp
		ts:				time		&log;
        ## Message Type
        msg_type:       string      &log &optional;
		## The requestor's MAC address.
		src_mac:		string		&log &optional;
        ## The responder's MAC address.
		mac_dst:		string		&log &optional;
        ## Source Protocol Address
        SPA:            addr        &log &optional;
        ## Source Hardware Address
        SHA:            string      &log &optional;
        ## Target Protocol Address
        TPA:            addr        &log &optional;
        ## Target Hardware Address
        THA:            string      &log &optional;
		## Bad Arp Explanation
		bad_explain:	string		&log &optional;
	};

	global log_arp: event(rec: Info);
}

event bro_init() &priority=5
{
	Log::create_stream(ARP::LOG, [$columns=Info, $ev=log_arp]);
}

event arp_request(mac_src: string, mac_dst: string, SPA: addr, SHA: string, TPA: addr, THA: string) &priority=5
{
    local info: Info;
	info$ts        = network_time();
    info$msg_type  = "request";
	info$src_mac   = mac_src;
	info$mac_dst   = mac_dst;
	info$SPA       = SPA;
	info$SHA       = SHA;
    info$TPA       = TPA;
    info$THA       = THA;

    Log::write(ARP::LOG, info);
}

event arp_reply(mac_src: string, mac_dst: string, SPA: addr, SHA: string, TPA: addr, THA: string) &priority=5
{
    local info: Info;
    info$ts        = network_time();
    info$msg_type  = "reply";
    info$src_mac   = mac_src;
    info$mac_dst   = mac_dst;
    info$SPA       = SPA;
    info$SHA       = SHA;
    info$TPA       = TPA;
    info$THA       = THA;

    Log::write(ARP::LOG, info);
}

event bad_arp(SPA: addr, SHA: string, TPA: addr, THA: string, explanation: string) &priority=5
{
    local info: Info;
    info$ts        = network_time();
    info$msg_type  = "bad";
    info$SPA       = SPA;
    info$SHA       = SHA;
    info$TPA       = TPA;
    info$THA       = THA;
    info$bad_explain = explanation;

    Log::write(ARP::LOG, info);
}
