##! TCP Protocol Analyzer of Last Resort.
##! Used when no other detailed TCP analyzers attached to a connection.


module TCP_BACKUP;

export {
    redef enum Log::ID += { LOG };

    type Info: record {
        ## Timestamp for when the event happened.
        ts :                time    &log;
        ## Unique ID for the connection.
        uid :               string  &log;
        ## The connection's 4-tuple of endpoint addresses/ports.
        id :                conn_id &log;
        ## Whether the packet came from the originator
        is_orig :           bool    &log;
        ## TCP sequence number
        sequence :          count   &log;
        ## Ack sequence number
        ack :               count   &log;
        ## TCP Flags present
        flags :             string  &log;
        ## Total payload size
        payload_len :       count   &log;
        ## Captured payload
        excerpt :           string  &log;
        ## Original captured payload size (bytes). Note that this may be different 
        ## than the size of the hex representation in excerpt.
        excerpt_size :      count   &log;
        ## Total payload size
        payload_size :      count   &log;
        ## Entropy of the payload
        entropy :           double  &log &optional;
    };

    ## Data bytes to record in a TCP request with no protocol-specific children analyzers.
    global tcp_excerpt_size : count = 64 &redef;

    global generate_tcp_logs: bool = T &redef;
}

event bro_init()
{
    Log::create_stream(TCP_BACKUP::LOG, [$columns=Info, $path="tcp"]);
}

event tcp_backup_event(c: connection, is_orig: bool, flags: string, seq: count, ack: count, len: count, payload: string)
{
    if (! generate_tcp_logs) {
        return;
    }
    local tcpinfo : Info;
    tcpinfo$ts          = network_time();
    tcpinfo$uid         = c$uid;
    tcpinfo$id          = c$id;
    tcpinfo$is_orig     = is_orig;
    tcpinfo$flags       = flags;
    tcpinfo$sequence    = seq;
    tcpinfo$ack         = ack;
    tcpinfo$payload_len = len;

    tcpinfo$entropy     = check_entropy(payload);

    if (|payload| > tcp_excerpt_size)
    {
        tcpinfo$excerpt = sub_bytes(payload, 0, tcp_excerpt_size);
        tcpinfo$excerpt_size = tcp_excerpt_size;
    }
    else
    {
        tcpinfo$excerpt = payload;
        tcpinfo$excerpt_size = |payload|;
    }
    
    tcpinfo$payload_size = |payload|;
    
    Log::write(TCP_BACKUP::LOG, tcpinfo);
}



