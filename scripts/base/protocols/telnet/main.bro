##! Implements base functionality for telnet analysis.
##! Generates the Telnet.log file.

module Telnet;

export {
	redef enum Log::ID += { LOG };
	
	const default_capture_password = F &redef;	
	
	type Info: record {
		## Timestamp for when the event happened.
		ts:     			time    &log;
		## Unique ID for the connection.
		uid:    			string	&log;
		## The connection's 4-tuple of endpoint addresses/ports.
		id:     			conn_id	&log;
		
		capture_password:	bool	&default=default_capture_password;
		flag:				string	&optional &log;
		data:			  	string 	&optional &log;
	};

	## Event that can be handled to access the telnet record as it is sent on
	## to the logging framework.
	global log_telnet: event(rec: Info);
}

const ports = { 23/tcp };
redef likely_server_ports += { ports };

event bro_init() &priority=5
{
	Log::create_stream(Telnet::LOG, [$columns=Info, $ev=log_telnet, $path="telnet"]);
	Analyzer::register_for_ports(Analyzer::ANALYZER_TELNET, ports);
}

event telnet_username_event(c: connection, username: string)
{
	local info: Info;

	info$ts = network_time();
	info$uid = c$uid;
	info$id = c$id;

	info$flag = "username";
	info$data = username;

	Log::write(Telnet::LOG, info);
}

event telnet_password_event(c: connection, password: string)
{
	local info: Info;

	info$ts = network_time();
	info$uid = c$uid;
	info$id = c$id;

	info$flag = "password";
	if (info$capture_password) 
		info$data = password;
	else 
		info$data = "(redacted)";
		
	Log::write(Telnet::LOG, info);
}

event telnet_login_event(c: connection, username: string, password: string, success: bool)
{
	local info: Info;

	info$ts = network_time();
	info$uid = c$uid;
	info$id = c$id;

	info$data = username;

	if (success)
		info$flag = "login-success";
	else 
		info$flag = "login-failed";

	info$data += ":";
	if (info$capture_password)
		info$data += password;
	else
		info$data += "(redacted)";

	Log::write(Telnet::LOG, info);
}

event telnet_sent_event(c: connection, data: string)
{
	local info: Info;
	info$ts = network_time();
	info$uid = c$uid;
	info$id = c$id;

	info$flag = "sent";
	info$data = data;

	Log::write(Telnet::LOG, info);
}

event telnet_received_event(c: connection, data: string)
{
	local info: Info;
	info$ts = network_time();
	info$uid = c$uid;
	info$id = c$id;

	info$flag = "received";
	info$data = data;

	Log::write(Telnet::LOG, info);
}

event telnet_data_event(c: connection, data: string)
{
	local info: Info;
	info$ts = network_time();
	info$uid = c$uid;
	info$id = c$id;

	info$flag = "data";
	info$data = data;

	Log::write(Telnet::LOG, info);

}
