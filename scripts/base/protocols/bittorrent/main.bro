##! Developed by Patrick Kelley for PacketSled
##! BitTorrent Protocol Detection
##!
##! Updated by Aaron Eppert - April 2016
##!

module BITTORRENT;

export {
    redef enum Log::ID += { LOG };
    type MSG_TYPE: enum {
        TRACKER_REQUEST,
        TRACKER_RESPONSE,
        PEER_HANDSHAKE,
    } &redef;

    type Info: record {
        ## Timestamp
        ts:        time    &log;
        ## Unique ID for the connection.
        uid:       string  &log;
        ## The connection's 4-tuple of endpoint addresses/ports.
        id:        conn_id &log;
        ## Message Type
        msg_type:   set[MSG_TYPE] &log &optional;
        ## Bittorrent uri
        uri:       string  &log &optional;
        ## Peer ID
        peer_id:   string  &log &optional;
        ## Info Hash
        info_hash: string  &log &optional;
    };

    global log_bittorrent: event(rec: Info);
}

redef record connection += {
    bittorrent:   Info &optional;
};

const ports = { 6881/tcp, 6882/tcp, 6883/tcp, 6884/tcp, 6885/tcp };
redef likely_server_ports += { ports };

event bro_init() &priority=5
{
    Log::create_stream(BITTORRENT::LOG, [$columns=BITTORRENT::Info, $ev=log_bittorrent]);
    Analyzer::register_for_ports(Analyzer::ANALYZER_BITTORRENT, ports);
}

function set_session(c: connection): Info
{
    local l: Info;
    l$ts  = network_time();
    l$id  = c$id;
    l$uid = c$uid;
    l$msg_type = set();
    return l;
}

function full_session(c: connection, uri: string): Info
{
    local l: Info = set_session(c);
    l$uri = uri;
    return l;
}

event bittorrent_peer_handshake(c: connection, is_orig: bool, reserved: string, info_hash: string, peer_id: string) &priority=5
{
    local pinfo: Info;
    pinfo = set_session(c);
    pinfo$info_hash = bytestring_to_hexstr(unescape_URI(info_hash));
    add pinfo$msg_type[PEER_HANDSHAKE];

    pinfo$peer_id = bytestring_to_hexstr(unescape_URI(peer_id));
    c$bittorrent = pinfo;
}

event bittorrent_peer_handshake(c: connection, is_orig: bool, reserved: string, info_hash: string, peer_id: string) &priority=-5
{
    Log::write(BITTORRENT::LOG, c$bittorrent);
}

# event bittorrent_peer_keep_alive(c: connection, is_orig: bool) &priority=5
# {
#     local pinfo: Info;
#     pinfo = set_session(c);
#     c$bittorrent = pinfo;
# }
#
# event bittorrent_peer_keep_alive(c: connection, is_orig: bool) &priority=-5
# {
#     Log::write(BITTORRENT::LOG, c$bittorrent);
# }
#
# event bittorrent_peer_choke(c: connection, is_orig: bool) &priority=5
# {
#     local pinfo: Info;
#     pinfo = set_session(c);
#     c$bittorrent = pinfo;
# }
#
# event bittorrent_peer_choke(c: connection, is_orig: bool) &priority=-5
# {
#     Log::write(BITTORRENT::LOG, c$bittorrent);
# }
#
# event bittorrent_peer_unchoke(c: connection, is_orig: bool) &priority=5
# {
#         local pinfo: Info;
#         pinfo = set_session(c);
#         c$bittorrent = pinfo;
# }
#
# event bittorrent_peer_unchoke(c: connection, is_orig: bool) &priority=-5
# {
#     Log::write(BITTORRENT::LOG, c$bittorrent);
# }
#
# event bittorrent_peer_interested(c: connection, is_orig: bool) &priority=5
# {
#     local pinfo: Info;
#     pinfo = set_session(c);
#     c$bittorrent = pinfo;
# }
#
# event bittorrent_peer_interested(c: connection, is_orig: bool) &priority=-5
# {
#     Log::write(BITTORRENT::LOG, c$bittorrent);
# }
#
# event bittorrent_peer_not_interested(c: connection, is_orig: bool) &priority=5
# {
#     local pinfo: Info;
#     pinfo = set_session(c);
#     c$bittorrent = pinfo;
# }
#
# event bittorrent_peer_not_interested(c: connection, is_orig: bool) &priority=-5
# {
#     Log::write(BITTORRENT::LOG, c$bittorrent);
# }
#
# event bittorrent_peer_have(c: connection, is_orig: bool, piece_index: count) &priority=5
# {
#     local pinfo: Info;
#     pinfo = set_session(c);
#     c$bittorrent = pinfo;
# }
#
# event bittorrent_peer_have(c: connection, is_orig: bool, piece_index: count) &priority=-5
# {
#     Log::write(BITTORRENT::LOG, c$bittorrent);
# }

event bt_tracker_request(c: connection, uri: string, headers: bt_tracker_headers) &priority=5
{
    local pinfo: Info;
    pinfo = full_session(c, uri);
    add pinfo$msg_type[TRACKER_REQUEST];
    c$bittorrent = pinfo;
}

event bt_tracker_request(c: connection, uri: string, headers: bt_tracker_headers) &priority=-5
{
    Log::write(BITTORRENT::LOG, c$bittorrent);
}

event bt_tracker_response(c: connection, status:count, headers: bt_tracker_headers, peers: bittorrent_peer_set, benc: bittorrent_benc_dir) &priority=5
{
    local pinfo: Info;
    pinfo = set_session(c);
    add pinfo$msg_type[TRACKER_RESPONSE];
    c$bittorrent = pinfo;
}

event bt_tracker_response(c: connection, status:count, headers: bt_tracker_headers, peers: bittorrent_peer_set, benc: bittorrent_benc_dir) &priority=-5
{
    Log::write(BITTORRENT::LOG, c$bittorrent);
}
