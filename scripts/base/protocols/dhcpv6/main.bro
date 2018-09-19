module DHCPV6;

export {
  const available = T;

  redef enum Log::ID += { LOG };

	type Info: record {
		## Timestamp for when the event happened.
		ts:       time            &log;
		## Unique ID for the connection.
		uid:      string          &log;
		## The connection's 4-tuple of endpoint addresses/ports.
		id:       conn_id         &log;
    ## Transaction ID
    tid:      count           &log &optional;
    ## DHCPV6 Command
    msgtype:  string          &log &optional;
    ## DHCPV6 Options
    options:  DHCPV6::Options &log &optional;
	};

	global log_dhcpv6: event(rec: DHCPV6::Info);
}

const ports = { 546/udp, 547/udp };
redef likely_server_ports += { ports };

redef record connection += {
	dhcpv6: Info &optional;
};

event bro_init() &priority=30
{
  Log::create_stream(DHCPV6::LOG, [$columns=DHCPV6::Info, $ev=log_dhcpv6, $path="dhcpv6"]);
  Analyzer::register_for_ports(Analyzer::ANALYZER_DHCPV6, ports);
}

function set_session(c: connection)
{
  if ( ! c?$dhcpv6 ) {
    add c$service["dhcpv6"];

    local info: DHCPV6::Info;

    info$ts  = network_time();
    info$id  = c$id;
    info$uid = c$uid;

    c$dhcpv6 = info;
  }
}

event dhcpv6_solicit(c: connection, is_orig: bool, tid: count, options: DHCPV6::Options)
{
	set_session(c);
  c$dhcpv6$msgtype = "DHCPV6_SOLICIT";
  c$dhcpv6$options = options;

  Log::write(DHCPV6::LOG, c$dhcpv6);
}

event dhcpv6_advertise(c: connection, is_orig: bool, tid: count, options: DHCPV6::Options)
{
	set_session(c);
  c$dhcpv6$msgtype = "DHCPV6_ADVERTISE";
  c$dhcpv6$options = options;

  Log::write(DHCPV6::LOG, c$dhcpv6);
}

event dhcpv6_request(c: connection, is_orig: bool, tid: count, options: DHCPV6::Options)
{
	set_session(c);
  c$dhcpv6$msgtype = "DHCPV6_REQUEST";
  c$dhcpv6$options = options;

  Log::write(DHCPV6::LOG, c$dhcpv6);
}

event dhcpv6_reply(c: connection, is_orig: bool, tid: count, options: DHCPV6::Options)
{
	set_session(c);
  c$dhcpv6$msgtype = "DHCPV6_REPLY";
  c$dhcpv6$options = options;

  Log::write(DHCPV6::LOG, c$dhcpv6);
}

event dhcpv6_renew(c: connection, is_orig: bool, tid: count, options: DHCPV6::Options)
{
	set_session(c);
  c$dhcpv6$msgtype = "DHCPV6_RENEW";
  c$dhcpv6$options = options;

  Log::write(DHCPV6::LOG, c$dhcpv6);
}

event dhcpv6_release(c: connection, is_orig: bool, tid: count, options: DHCPV6::Options)
{
	set_session(c);
  c$dhcpv6$msgtype = "DHCPV6_RELEASE";
  c$dhcpv6$options = options;

  Log::write(DHCPV6::LOG, c$dhcpv6);
}

event dhcpv6_info_req(c: connection, is_orig: bool, tid: count, options: DHCPV6::Options)
{
	set_session(c);
  c$dhcpv6$msgtype = "DHCPV6_INFORMATION_REQUEST";
  c$dhcpv6$options = options;

  Log::write(DHCPV6::LOG, c$dhcpv6);
}
