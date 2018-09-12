##! UDP Protocol Analyzer of Last Resort.
##! Used when no other detailed UDP analyzers attached to a connection.


module UDP_BACKUP;

export {
    redef enum Log::ID += { LOG };

    type Info: record {
        ## Timestamp for when the event happened.
        ts:     time    &log;
        ## Unique ID for the connection.
        uid:    string  &log;
        ## The connection's 4-tuple of endpoint addresses/ports.
        id:     conn_id &log;
        ## Whether the packet came from the originator
        is_orig :         bool      &log;
        ## Captured payload
        excerpt :         string    &log;
        ## Original captured payload size (bytes). Note that this may be different 
        ## than the size of the hex representation in excerpt.
        excerpt_size :    count     &log;
        ## Total payload size
        payload_size :    count     &log;
        ## Entropy of the payload
        entropy :           double  &log &optional;
    };

    ## Data bytes to record in a UDP request with no protocol-specific children analyzers.
    global udp_excerpt_size : count = 64 &redef;

    global generate_udp_logs: bool = T &redef;
}


event bro_init()
{
    Log::create_stream(UDP_BACKUP::LOG, [$columns=Info, $path="udp"]);
}

event udp_backup_event(u: connection, is_orig: bool, contents: string)
{
    if (!generate_udp_logs) {
        return;
    }

    local udpinfo : Info;
    udpinfo$ts  = network_time();
    udpinfo$uid = u$uid;
    udpinfo$id  = u$id;
    udpinfo$is_orig = is_orig;

    udpinfo$entropy = check_entropy(contents);
    
    if (|contents| > udp_excerpt_size)
    {
        udpinfo$excerpt = sub_bytes(contents, 0, udp_excerpt_size);
        udpinfo$excerpt_size = udp_excerpt_size;
    }
    else
    {
        udpinfo$excerpt = contents;
        udpinfo$excerpt_size = |contents|;
    }
    
    udpinfo$payload_size = |contents|;
    
    Log::write(UDP_BACKUP::LOG, udpinfo);
}



