@load ./consts
@load base/frameworks/dpd

module DCE_RPC_LSA;

export {
  const available = T;

	redef enum Log::ID += { LOG };

	type Info: record {
		## Timestamp for when the event happened.
		ts         : time     &log;
		## Unique ID for the connection.
		uid        : string   &log;
		## The connection's 4-tuple of endpoint addresses/ports.
		id         : conn_id  &log;

    getusername_req: DCE_RPC::LSA_GETUSERNAME_REQUEST &log &optional;
	};
}

redef record connection += {
	dce_rpc_lsa: Info &optional;
};

redef record DCE_RPC_LSA::Info += {
  ps_family: int &log &default=6;
  ps_proto: int &log &default=60005;
};

function set_session(c: connection)
{
  if ( ! c?$dce_rpc_lsa ) {
    add c$service["dce_rpc_lsa"];

    local info: DCE_RPC_LSA::Info;

    info$ts  = network_time();
    info$id  = c$id;
    info$uid = c$uid;

    c$dce_rpc_lsa = info;
  }
}

event bro_init() &priority=5
{
	Log::create_stream(DCE_RPC_LSA::LOG, [$columns=Info, $path="dce_rpc_lsa"]);
}

event lsa_getusername_request(c: connection, request: DCE_RPC::LSA_GETUSERNAME_REQUEST)
{
  set_session(c);
  c$dce_rpc_lsa$getusername_req = request;
  Log::write(DCE_RPC_LSA::LOG, c$dce_rpc_lsa);
}
