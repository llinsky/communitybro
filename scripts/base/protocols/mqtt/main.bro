module MQTT;

@load ./consts.bro

export {
    redef enum Log::ID += { LOG };
    
    type Info: record {
        ## Timestamp for when the event happened.
        ts          : time    		    &log;
        ## Unique ID for the connection.
        uid         : string  		    &log;
        ## The connection's 4-tuple of endpoint addresses/ports.
        id          : conn_id 		    &log;
        msg_type    : count             &optional &log;
        conn        : MQTT::CONNECT     &optional &log;
        connack     : MQTT::CONNACK     &optional &log;
        pub         : MQTT::PUBLISH     &optional &log;
        puback      : MQTT::PUBACK      &optional &log;
        sub         : MQTT::SUBSCRIBE   &optional &log;
        suback      : MQTT::SUBACK      &optional &log;
        unsubscribe : MQTT::UNSUBSCRIBE &optional &log;
        unsuback    : MQTT::UNSUBACK    &optional &log;
    };

    global log_mqtt: event(rec: Info);
}

const ports = { 1883/tcp };

redef likely_server_ports += { ports };

event bro_init() &priority=5
{
    Log::create_stream(MQTT::LOG, [$columns=Info, $ev=log_mqtt, $path="mqtt"]);
    Analyzer::register_for_ports(Analyzer::ANALYZER_MQTT, ports);
}

event mqtt_conn(c: connection, msg_type: count, msg: MQTT::CONNECT)
{
    local info: Info;

    info$ts  	  	= network_time();
    info$uid 	  	= c$uid;
    info$id  	  	= c$id;
    info$conn       = msg;
    info$msg_type   = msg_type;

    Log::write(MQTT::LOG, info);
}

event mqtt_connack(c: connection, msg_type: count, msg: MQTT::CONNACK)
{
    local info: Info;

    info$ts  		 = network_time();
    info$uid 		 = c$uid;
    info$id  	 	 = c$id;
    info$connack     = msg;
    info$msg_type   = msg_type;

    Log::write(MQTT::LOG, info);
}

event mqtt_pub(c: connection, msg_type: count, msg: MQTT::PUBLISH)
{
    local info: Info;

    info$ts 		= network_time();
    info$uid 		= c$uid;
    info$id  		= c$id;
    info$pub        = msg;
    info$msg_type   = msg_type;


    if (info?$pub && info$pub?$message) {
        info$pub$message = escape_string(info$pub$message);
    }
   
    Log::write(MQTT::LOG, info);
}

event mqtt_puback(c: connection, msg_type: count, msg: MQTT::PUBACK)
{
    local info: Info;

    info$ts  		= network_time();
    info$uid 		= c$uid;
    info$id  		= c$id;
    info$puback 	= msg;
    info$msg_type   = msg_type;

    Log::write(MQTT::LOG, info);
}

event mqtt_sub(c: connection, msg_type: count, msg: MQTT::SUBSCRIBE)
{
    local info: Info;

    info$ts  			= network_time();
    info$uid 			= c$uid;
    info$id  			= c$id;
    info$sub            = msg;
    info$msg_type       = msg_type;

    Log::write(MQTT::LOG, info);
}

event mqtt_suback(c: connection, msg_type: count, msg: MQTT::SUBACK)
{
    local info: Info;

    info$ts  			= network_time();
    info$uid 			= c$uid;
    info$id  			= c$id;
    info$suback         = msg;
    info$msg_type       = msg_type;

    Log::write(MQTT::LOG, info);
}

event mqtt_unsub(c: connection, msg_type: count, msg: MQTT::UNSUBSCRIBE)
{
    local info: Info;

    info$ts 		= network_time();
    info$uid 		= c$uid;
    info$id  		= c$id;
    info$unsubscribe = msg;
    info$msg_type   = msg_type;
 
    Log::write(MQTT::LOG, info);
}

event mqtt_unsuback(c: connection, msg_type: count, msg: MQTT::UNSUBACK)
{
    local info: Info;

    info$ts 		= network_time();
    info$uid 		= c$uid;
    info$id  		= c$id;
    info$unsuback 	= msg;
    info$msg_type   = msg_type;

    Log::write(MQTT::LOG, info);
}

event mqtt_pingreq(c: connection, msg_type: count)
{
    local info: Info;

    info$ts  		= network_time();
    info$uid 		= c$uid;
    info$id  		= c$id;
    info$msg_type   = msg_type;

    Log::write(MQTT::LOG, info);
}

event mqtt_pingres(c: connection, msg_type: count)
{
    local info: Info;

    info$ts  		= network_time();
    info$uid 		= c$uid;
    info$id  		= c$id;
    info$msg_type   = msg_type;

    Log::write(MQTT::LOG, info);
}

event mqtt_disconnect(c: connection, msg_type: count)
{
    local info: Info;

    info$ts  		= network_time();
    info$uid 		= c$uid;
    info$id  		= c$id;
    info$msg_type   = msg_type;

    Log::write(MQTT::LOG, info);
}
