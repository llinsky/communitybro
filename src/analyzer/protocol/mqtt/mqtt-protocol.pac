##! MQTT control packet parser
##! Based on the initial work of Supriya Sudharani Kumaraswamy via the sponsorship
##! of Leo Linsky of PacketSled
##!
##! Rewritten by Aaron Eppert and Chris Hinshaw of PacketSled
##!

enum MQTT_msg_type {
    MQTT_RESERVED    = 0,
    MQTT_CONNECT     = 1,
    MQTT_CONNACK     = 2,
    MQTT_PUBLISH     = 3,
    MQTT_PUBACK      = 4,
    MQTT_PUBREC      = 5,
    MQTT_PUBREL      = 6,
    MQTT_PUBCOMP     = 7,
    MQTT_SUBSCRIBE   = 8,
    MQTT_SUBACK      = 9,
    MQTT_UNSUBSCRIBE = 10,
    MQTT_UNSUBACK    = 11,
    MQTT_PINGREQ     = 12,
    MQTT_PINGRESP    = 13,
    MQTT_DISCONNECT  = 14,
};

type MQTT_will_obj = record {
    will_topiclen 	: uint16;
    will_topic	  	: bytestring &length = will_topiclen;
    will_msglen   	: uint16; 
    will_msg  	  	: bytestring &length = will_msglen;
};

type MQTT_username_obj = record {
    uname_len   	: uint16; 
    uname 			: bytestring &length = uname_len;
};

type MQTT_password_obj = record {
    pass_len  		: uint16; 
    pass 	  		: bytestring &length = pass_len;
};

type MQTT_connect(hdrlen: uint8, QoS: uint8, dup: uint8, retain: uint8) = record {
    len              : uint16;
    protocol_name    : bytestring &length=len;
    protocol_version : int8;
    connect_flags    : uint8;
    keep_alive       : uint16;
    clientID_len     : uint16;
    client_id        : bytestring &length=clientID_len;
    will_fields      : case will of {
        1 		     -> will_objs: MQTT_will_obj;
        default      -> no_will_fileds: empty;
    };
    username_fields  : case username of {
        1 		     -> uname_objs: MQTT_username_obj;
        default      -> no_uname_fields: empty;
    };
    password_fields  : case password of {
        1		     -> pass_objs: MQTT_password_obj;
        default      -> no_pass_fields: empty;
    };
} &let {
    username      	: uint8 = (connect_flags  & 0x80) != 0;
    password      	: uint8 = (connect_flags  & 0x40) != 0;
    clean_session 	: uint8 = (connect_flags  & 0x02) != 0;
    will          	: uint8 = (connect_flags  & 0x04) != 0;
    will_retain   	: uint8 = ((connect_flags & 0x20) != 0) &if(will);
    will_QoS      	: uint8 = ((connect_flags & 0x18) >> 3) &if(will);
};

type MQTT_connectack(hdrlen: uint8, QoS: uint8, dup: uint8, retain: uint8) = record {
    reserved_field 	: uint8;
    return_code 	: uint8;
};

type MQTT_publish(hdrlen: uint8, QoS: uint8, dup: uint8, retain: uint8) = record {
    topic_len    	: uint16;
    topic        	: bytestring &length=topic_len;
    msgid_field	    : case QoS of {
        1		    -> confirm_req	        : uint16;
        2		    -> four_step_hs	        : uint16;
        default	    -> nothing		        : empty;
    };
    publish_field   : case QoS of {
        1		    -> publish_with_qos_1	: bytestring &length=hdrlen-topic_len-4;
        2		    -> publish_with_qos_2	: bytestring &length=hdrlen-topic_len-4;
        default	    -> public_with_qos_def  : bytestring &length=hdrlen-topic_len-2;
    };
};

type MQTT_puback(hdrlen: uint8, QoS: uint8, dup: uint8, retain: uint8) = record {
    msg_id 			: uint16;
} ;

type MQTT_subscribe_topic = record {
    topic_len       : uint16;
    subscribe_topic : bytestring &length=topic_len;
    requested_QoS   : uint8;
};

type MQTT_subscribe(hdrlen: uint8, QoS: uint8, dup: uint8, retain: uint8) = record {
    msg_id 			: uint16;
    topics 			: MQTT_subscribe_topic[];
};

type MQTT_suback(hdrlen: uint8, QoS: uint8, dup: uint8, retain: uint8) = record {
    msg_id      	: uint16;
    granted_QoS 	: uint8;
};

type MQTT_unsubscribe_topic = record {
    topic_len       : uint16;
    unsub_topic     : bytestring &length=topic_len;
};

type MQTT_unsubscribe(hdrlen: uint8, QoS: uint8, dup: uint8, retain: uint8) = record {
    msg_id 			: uint16;
    topics 			: MQTT_unsubscribe_topic[];
};

type MQTT_unsuback(hdrlen: uint8, QoS: uint8, dup: uint8, retain: uint8) = record {
    msg_id 			: uint16;
}; 

type MQTT_message = record {
    fixed_header    : uint8;
    hdrlen          : uint8;
    variable_header : case msg_type of {
        MQTT_CONNECT     -> connect_packet      : MQTT_connect(hdrlen, QoS, dup, retain);
        MQTT_CONNACK     -> connectack_packet   : MQTT_connectack(hdrlen, QoS, dup, retain);
        MQTT_SUBSCRIBE   -> subscribe_packet    : MQTT_subscribe(hdrlen, QoS, dup, retain);
        MQTT_SUBACK      -> suback_packet       : MQTT_suback(hdrlen, QoS, dup, retain);
        MQTT_PUBLISH     -> publish_packet      : MQTT_publish(hdrlen, QoS, dup, retain);
        MQTT_PUBACK      -> puback_packet       : MQTT_puback(hdrlen, QoS, dup, retain);
        #MQTT_PUBREC      -> pubrec_packet      : MQTT_puback(hdrlen, QoS, dup, retain);
        #MQTT_PUBREL      -> pubrel_packet      : MQTT_puback(hdrlen, QoS, dup, retain);
        #MQTT_PUBCOMP     -> pubcomp_packet     : MQTT_puback(hdrlen, QoS, dup, retain);
        MQTT_UNSUBSCRIBE -> unsubscribe_packet  : MQTT_unsubscribe(hdrlen, QoS, dup, retain);
        MQTT_UNSUBACK    -> unsuback_packet     : MQTT_unsuback(hdrlen, QoS, dup, retain);
        default          -> none                : empty;
    } &requires(QoS, dup, retain);
} &let {
    msg_type        : uint8 = (fixed_header  >>  4);
    dup             : uint8 = ((fixed_header &   0x08) >> 3); 
    QoS             : uint8 = ((fixed_header &   0x06) >> 1);
    retain          : uint8 = (fixed_header  &   0x01);
};

type MQTT_PDU(is_orig: bool) = record {
    mqtt_messages   : MQTT_message[] &until($input.length() == 0); 
} &byteorder=bigendian; #&exportsourcedata;
