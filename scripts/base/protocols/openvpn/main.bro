# Bro OpenVPN Analyzer
# Copyright (C) 2017 CommunityBro

##! Developed by Leo Linsky for Packetsled. Copyright 2016.

##! Implements base functionality for openvpn analysis.
##! Generates the Openvpn.log file.

# This script is UDP/TCP agnostic.

module Openvpn;

export {
    redef enum Log::ID += { LOG };

    type Info: record {
        ## Timestamp for when the event happened.
        ts:     time    &log;
        ## Unique ID for the connection.
        uid:    string  &log;
        ## The connection's 4-tuple of endpoint addresses/ports.
        id:     conn_id &log;
        ## Event info
        ev:     string  &log;
    };

    ## Event that can be handled to access the openvpn record as it is sent on
    ## to the logging framework.
    global log_openvpn: event(rec: Info);
}

redef record connection += {
    openvpn: bool &optional;
};

event bro_init() &priority=5
{
    Log::create_stream(Openvpn::LOG, [$columns=Info, $ev=log_openvpn, $path="openvpn"]);
}

event openvpn_hard_reset(c: connection, proto: string)
{
    local info: Info;
    info$ts  = network_time();
    info$uid = c$uid;
    info$id  = c$id;
    info$ev  = proto;

    c$openvpn = T;

    Log::write(Openvpn::LOG, info);
}

event openvpn_soft_reset(c: connection, source: string)
{
    local info: Info;
    info$ts  = network_time();
    info$uid = c$uid;
    info$id  = c$id;
    info$ev  = "SOFT RESET " + source;

    Log::write(Openvpn::LOG, info);
}

event openvpn_tlsestablished(c: connection)
{
    local info: Info;
    info$ts  = network_time();
    info$uid = c$uid;
    info$id  = c$id;
    info$ev = "TLS ESTABLISHED";

    Log::write(Openvpn::LOG, info);
}
