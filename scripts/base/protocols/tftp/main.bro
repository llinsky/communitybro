##! Developed by Leo Linsky for Packetsled. Copyright 2016.

##! Implements base functionality for TFTP analysis.
##! Generates the Tftp.log file.


# Note on data transfer modes: 
#	Three modes of transfer are currently  supported:  netascii ;  octet , 
#	raw  8 bit bytes; mail, netascii characters sent to a user rather than a
#	file.  Additional modes can be defined by pairs of cooperating hosts.

@load base/utils/site
@load base/frameworks/notice


module TFTP;

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		## Timestamp for when the event happened.
		ts:     		time    &log;
		## Unique ID for the connection.
		uid:    		string  &log;
		## The connection's 4-tuple of endpoint addresses/ports.
		id:     		conn_id &log;
		## Specifies initial request type (write or read)
		request_type:	string	&log;
		## Filename requested
		filename:   	string	&log;
		## Data transfer mode
		mode:   		string	&log;
		## File size (bytes)
		filesize:		count	&log;
	};

	## Event that can be handled to access the TFTP record as it is sent on
	## to the logging framework.
	global log_tftp: event(rec: Info);

	redef enum Notice::Type += {
		OutboundTFTP,		# outbound TFTP seen
	};
}

redef record connection += {
	tftp: Info &optional;
};


global tftp_notice_count: table[addr] of count &default = 0 &read_expire = 7 days;

# Establish the variable for tracking expected connections to transfer to the second connection
global tftp_data_expected: table[addr, port, addr] of Info &read_expire=5mins;



event bro_init() &priority=5
{
	Log::create_stream(TFTP::LOG, [$columns=Info, $ev=log_tftp, $path="tftp"]);
}


event tftp_write_request(u: connection, filename: string, mode: string)
{
	local src = u$id$orig_h;
	local src_p = u$id$orig_p;
	local dest = u$id$resp_h;

	if ( Site::is_local_addr(src) && ! Site::is_local_addr(dest) &&
		++tftp_notice_count[src] == 1 ) {
		NOTICE([$note=OutboundTFTP, $conn=u, $msg=fmt("outbound TFTP: %s -> %s", src, dest),
               	$sub=fmt("Severity: 4"),
       		$ps_defining_query=fmt("src_ip = %s dest_ip = %s proto = tftp", src, dest)]);
	}
		
	if ([src, src_p, dest] in tftp_data_expected) {
		event conn_weird("duplicate_tftp_request_tuple", u, " (wrq)");
	}
	
	local token: Info;
	token$ts=network_time();
	token$uid=u$uid;
	token$id=u$id;
	token$request_type="w";
	token$filename=filename;
	token$mode=mode;
	
	tftp_data_expected[src, src_p, dest] = token;


	Analyzer::schedule_analyzer(dest, src, src_p,
	Analyzer::ANALYZER_TFTP, 5mins);
}

event tftp_read_request(u: connection, filename: string, mode: string)
{
	local src = u$id$orig_h;
	local src_p = u$id$orig_p;
	local dest = u$id$resp_h;

	if ( Site::is_local_addr(src) && ! Site::is_local_addr(dest) &&
	     ++tftp_notice_count[src] == 1 ) {
		NOTICE([$note=OutboundTFTP, $conn=u, $msg=fmt("outbound TFTP: %s -> %s", src, dest),
                $sub=fmt("Severity: 4"),
                $ps_defining_query=fmt("src_ip = %s dest_ip = %s proto = tftp", src, dest)]);
	}
	
	if ([src, src_p, dest] in tftp_data_expected) {
		event conn_weird("duplicate_tftp_request_tuple", u, " (wrq)");
	}

	local token: Info;
	token$ts=network_time();
	token$uid=u$uid;
	token$id=u$id;
	token$request_type="r";
	token$filename=filename;
	token$mode=mode;

	tftp_data_expected[src, src_p, dest] = token;

	Analyzer::schedule_analyzer(dest, src, src_p,
        Analyzer::ANALYZER_TFTP, 5mins);
}

event tftp_reply(u: connection)
{
	if ("tftp" in u$service) {
		return; #Filter out wreq tftp sessions which generate two tftp_reply events
	}
	
	add u$service["tftp"];

	local dest = u$id$resp_h;
	local dest_p = u$id$resp_p;
	local src = u$id$orig_h;
	local src_p = u$id$orig_p;

	if ( [src, src_p, dest] in tftp_data_expected) {
		u$tftp = tftp_data_expected[src, src_p, dest];
		u$tftp$id$resp_p = dest_p;
	}
	else {
		event conn_weird("unexpected_tftp_reply", u, " ");
	}
}

#Currently unused
event tftp_error(u: connection, errmsg: string)
{

}

#Currently unused
event tftp_flow_done(u: connection) #, final_block_size: count)
{
	#This could also go in connection_state_remove (without the else)
	if (u ?$ tftp) {
		Log::write(TFTP::LOG, u$tftp);
	}
	else {
		event conn_weird("bad_tftp_flow", u, " ");
	}
}

event connection_state_remove(u: connection)
{
	if (u?$tftp) {
		Log::write(TFTP::LOG, u$tftp);
	}
}
