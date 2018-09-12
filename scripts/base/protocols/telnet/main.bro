## TELNET Protocol Analyzer
## Developed by Aaron Eppert and Patrick Kelley for PacketSled

module TELNET;

export {
	redef enum Log::ID += { LOG };
	const default_capture_password = F &redef;
	type Info: record {
		## Timestamp for when the event happened.
		ts:               time &log;
		## Unique ID for the connection.
		uid:              string  &log;
		## The connection's 4-tuple of endpoint addresses/ports.
		id:               conn_id &log &optional;
		## Telnet Session Behaviors
		display:		  string &log &optional;
		user:			  string &log &optional;
		client_user:	  string &log &optional;
		password:		  string &log &optional;
		line:			  string &log &optional;
	};

	## Event that can be handled to access the telnet record as it is sent on
	## to the logging framework.
global log_telnet: event(rec: Info);
}

redef record connection += {
	telnet: Info &optional;
};

const ports = { 23/tcp };
redef likely_server_ports += { ports };

event bro_init() &priority=5
{
    Log::create_stream(TELNET::LOG, [$columns=TELNET::Info, $ev=log_telnet, $path="telnet"]);
    Analyzer::register_for_ports(Analyzer::ANALYZER_TELNET, ports);
}

event login_display(c: connection, display: string)
{
	local rec: TELNET::Info = [$ts=network_time(), $id=c$id, $uid=c$uid, $display=display];
	c$telnet = rec;
	Log::write(TELNET::LOG, rec);
}

event login_failure(c: connection, user: string, client_user: string, password: string, line: string)
{
	local login_failure_rec: TELNET::Info = [$ts=network_time(), $id=c$id,$uid=c$uid,  $user=user, $client_user=client_user, $password=password, $line=line];
	c$telnet = login_failure_rec;
	Log::write(TELNET::LOG, login_failure_rec);
}

event login_success(c: connection, user: string, client_user: string, password: string, line: string)
{
	local login_success_rec: TELNET::Info = [$ts=network_time(), $id=c$id,$uid=c$uid,  $user=user, $client_user=client_user, $password=password, $line=line];
	c$telnet = login_success_rec;
	Log::write(TELNET::LOG, login_success_rec);
}

event login_input_line(c: connection, line: string)
{
	local login_input_line_rec: TELNET::Info = [$ts=network_time(), $id=c$id,$uid=c$uid,  $line=line];
	c$telnet = login_input_line_rec;
	Log::write(TELNET::LOG, login_input_line_rec);
}

event login_output_line(c: connection, line: string)
{
	local login_output_line_rec: TELNET::Info = [$ts=network_time(), $id=c$id,$uid=c$uid,  $line=line];
	c$telnet = login_output_line_rec;
	Log::write(TELNET::LOG, login_output_line_rec);
}
