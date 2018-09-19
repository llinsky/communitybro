# DHCPv6 Message Type according to RFC 3315.

type uint24 = record {
    byte1 	: uint8;
    byte2 	: uint8;
    byte3 	: uint8;
};

type uint128 = record {
    a1		: uint32;
    a2		: uint32;
    a3		: uint32;
    a4		: uint32;
};

function to_int(num: uint24): uint32
%{
    return (num->byte1() << 16) | (num->byte2() << 8) | num->byte3();
%}

enum DHCPV6_options {
    DHCPV6_OPTION_CLIENTID				=	1, # RFC3315
    DHCPV6_OPTION_SERVERID				=	2,  
    DHCPV6_OPTION_IA_NA					=	3,  
    DHCPV6_OPTION_IA_TA					=	4,  
    DHCPV6_OPTION_IAADDR				=	5,  
    DHCPV6_OPTION_ORO					=	6,  
    DHCPV6_OPTION_PREFERENCE			=	7,  
    DHCPV6_OPTION_ELAPSED_TIME			=	8,  
    DHCPV6_OPTION_RELAY_MSG				=	9,  
    DHCPV6_OPTION_NO_MSG_10				=	10,  
    DHCPV6_OPTION_AUTH					=	11,  
    DHCPV6_OPTION_UNICAST				=	12,  
    DHCPV6_OPTION_STATUS_CODE			=	13,  
    DHCPV6_OPTION_RAPID_COMMIT			=	14,  
    DHCPV6_OPTION_USER_CLASS			=	15,  
    DHCPV6_OPTION_VENDOR_CLASS			=	16,  
    DHCPV6_OPTION_VENDOR_OPTS			=	17,  
    DHCPV6_OPTION_INTERFACE_ID			=	18,  
    DHCPV6_OPTION_RECONF_MSG			=	19,  
    DHCPV6_OPTION_RECONF_ACCEPT			=	20,  
    DHCPV6_OPTION_SIP_SERVERS_DNS		=	21, # RFC3319
    DHCPV6_OPTION_SIP_SERVERS_ADDR		=	22, # RFC3319
    DHCPV6_OPTION_NAME_SERVERS			=	23, # RFC3646
    DHCPV6_OPTION_DOMAIN_LIST			=	24, # RFC3646
    DHCPV6_OPTION_IA_PD					=	25, # RFC3633
    DHCPV6_OPTION_IAPREFIX				=	26, # RFC3633
    DHCPV6_OPTION_NIS_SERVERS			=	27, # RFC3898
    DHCPV6_OPTION_NISP_SERVERS			=	28, # RFC3898
    DHCPV6_OPTION_NIS_DOMAIN_NAME		=	29, # RFC3898
    DHCPV6_OPTION_NISP_DOMAIN_NAME		=	30, # RFC3898
    DHCPV6_OPTION_SNTP_SERVERS			=	31, # RFC4075
    DHCPV6_OPTION_INFORMATION_REFRESH_TIME	=	32, # RFC4242
    DHCPV6_OPTION_BCMCS_SERVER_D		=	33, # RFC4280
    DHCPV6_OPTION_BCMCS_SERVER_A		=	34, # RFC4280
    DHCPV6_OPTION_NO_MSG_35				=	35,  
    DHCPV6_OPTION_GEOCONF_CIVIC			=	36, # RFC4776
    DHCPV6_OPTION_REMOTE_ID				=	37, # RFC4649
    DHCPV6_OPTION_SUBSCRIBER_ID			=	38, # RFC4580
    DHCPV6_OPTION_CLIENT_FQDN			=	39, # RFC4704
    DHCPV6_OPTION_PANA_AGENT			=	40, # paa-option
    DHCPV6_OPTION_NEW_POSIX_TIMEZONE	=	41, # RFC4833
    DHCPV6_OPTION_NEW_TZDB_TIMEZONE		=	42, # RFC4833
    DHCPV6_OPTION_ERO					=	43, # RFC4994
    DHCPV6_OPTION_LQ_QUERY				=	44, # RFC5007
    DHCPV6_OPTION_CLIENT_DATA			=	45, # RFC5007
    DHCPV6_OPTION_CLT_TIME				=	46, # RFC5007
    DHCPV6_OPTION_LQ_RELAY_DATA			=	47, # RFC5007
    DHCPV6_OPTION_LQ_CLIENT_LINK		=	48, # RFC5007
    DHCPV6_OPTION_MIP6_HNIDF			=	49, # RFC6610
    DHCPV6_OPTION_MIP6_VDINF			=	50, # RFC6610
    DHCPV6_OPTION_V6_LOST				=	51, # RFC5223
    DHCPV6_OPTION_CAPWAP_AC_V6			=	52, # RFC5417
    DHCPV6_OPTION_RELAY_ID				=	53, # RFC5460
    DHCPV6_OPTION_IPV6_ADDRESS_MOS		=	54, # RFC5678
    DHCPV6_OPTION_IPV6_FQDN_MOS			=	55, # RFC5678
    DHCPV6_OPTION_NTP_SERVER			=	56, # RFC5908
    DHCPV6_OPTION_V6_ACCESS_DOMAIN		=	57, # RFC5986
    DHCPV6_OPTION_SIP_UA_CS_LIST		=	58, # RFC6011
    DHCPV6_OPTION_BOOTFILE_URL			=	59, # RFC5970
    DHCPV6_OPTION_BOOTFILE_PARAM		=	60, # RFC5970
    DHCPV6_OPTION_CLIENT_ARCH_TYPE		=	61, # RFC5970
    DHCPV6_OPTION_NII					=	62, # RFC5970
    DHCPV6_OPTION_GEOLOCATION			=	63, # RFC6225
    DHCPV6_OPTION_AFTR_NAME				=	64, # RFC6334
    DHCPV6_OPTION_ERP_LOCAL_DOMAIN_NAME	=	65, # RFC6440
    DHCPV6_OPTION_RSOO					=	66, # RFC6422
    DHCPV6_OPTION_PD_EXCLUDE			=	67, # RFC6603
    DHCPV6_OPTION_VSS					=	68, # RFC6607
    DHCPV6_OPTION_MIP6_IDINF			=	69, # RFC6610
    DHCPV6_OPTION_MIP6_UDINF			=	70, # RFC6610
    DHCPV6_OPTION_MIP6_HNP				=	71, # RFC6610
    DHCPV6_OPTION_MIP6_HAA				=	72, # RFC6610
    DHCPV6_OPTION_MIP6_HAF				=	73, # RFC6610
    DHCPV6_OPTION_RDNSS_SELECTION		=	74, # RFC6731
    DHCPV6_OPTION_KRB_PRINCIPAL_NAME	=	75, # RFC6784
    DHCPV6_OPTION_KRB_REALM_NAME		=	76, # RFC6784
    DHCPV6_OPTION_KRB_DEFAULT_REALM_NAME =	77, # RFC6784
    DHCPV6_OPTION_KRB_KDC				=	78, # RFC6784
    DHCPV6_OPTION_CLIENT_LINKLAYER_ADDR	=	79, # RFC6939
    DHCPV6_OPTION_LINK_ADDRESS			=	80, # RFC6977
    DHCPV6_OPTION_RADIUS				=	81, # RFC7037
    DHCPV6_OPTION_SOL_MAX_RT			=	82, # RFC7083
    DHCPV6_OPTION_INF_MAX_RT			=	83, # RFC7083
    DHCPV6_OPTION_ADDRSEL				=	84, # RFC7078
    DHCPV6_OPTION_ADDRSEL_TABLE			=	85, # RFC7078
    DHCPV6_OPTION_V6_PCP_SERVER			=	86, # RFC7291
    DHCPV6_OPTION_DHCPV4_MSG			=	87, # RFC7341
    DHCPV6_OPTION_DHCP4_O_DHCP6_SERVER	=	88 	# RFC7341
};

# Status Codes, from RFC 3315 section 24.4, and RFC 3633, 5007, 5460.
enum DHCPV6_status_codes {
    DHCPV6_STATUS_SUCCESS		 	= 0,
    DHCPV6_STATUS_UNSPECFAIL	 	= 1,
    DHCPV6_STATUS_NOADDRSAVAIL	 	= 2,
    DHCPV6_STATUS_NOBINDING	 		= 3,
    DHCPV6_STATUS_NOTONLINK	 		= 4,
    DHCPV6_STATUS_USEMULTICAST	 	= 5,
    DHCPV6_STATUS_NOPREFIXAVAIL		= 6,
    DHCPV6_STATUS_UNKNOWNQUERYTYPE	= 7,
    DHCPV6_STATUS_MALFORMEDQUERY	= 8,
    DHCPV6_STATUS_NOTCONFIGURED		= 9,
    DHCPV6_STATUS_NOTALLOWED		= 10,
    DHCPV6_STATUS_QUERYTERMINATED	= 11
};
 
# DHCPv6 message types, defined in section 5.3 of RFC 3315 
enum DHCPV6_message_type {
    DHCPV6_SOLICIT				= 1,
    DHCPV6_ADVERTISE			= 2,
    DHCPV6_REQUEST				= 3,
    DHCPV6_CONFIRM				= 4,
    DHCPV6_RENEW				= 5,
    DHCPV6_REBIND				= 6,
    DHCPV6_REPLY				= 7,
    DHCPV6_RELEASE				= 8,
    DHCPV6_DECLINE				= 9,
    DHCPV6_RECONFIGURE 			= 10,
    DHCPV6_INFORMATION_REQUEST 	= 11,
    DHCPV6_RELAY_FORW 			= 12,
    DHCPV6_RELAY_REPL 			= 13,
    DHCPV6_LEASEQUERY	   		= 14,	# RFC5007 
    DHCPV6_LEASEQUERY_REPLY	   	= 15,	# RFC5007 
    DHCPV6_LEASEQUERY_DONE	    = 16,	# RFC5460 
    DHCPV6_LEASEQUERY_DATA	    = 17,	# RFC5460 
    DHCPV6_RECONFIGURE_REQUEST  = 18,	# RFC6977 
    DHCPV6_RECONFIGURE_REPLY    = 19,	# RFC6977 
    DHCPV6_DHCPV4_QUERY	   		= 20,	# RFC7341 
    DHCPV6_DHCPV4_RESPONSE	   	= 21	# RFC7341 
};

enum DHCPV6_DUID_type {
    DUID_LLT	= 1,
    DUID_EN		= 2,
    DUID_LL		= 3,
    DUID_UUID	= 4	 # RFC6355 
};

enum DHCPV6_htype {
    HTYPE_ETHER     	= 1,
    HTYPE_IEEE802		= 6,
    HTYPE_FDDI			= 8,
    HTYPE_INFINIBAND	= 32, 
    HTYPE_IPMP			= 255
};

# Leasequery query-types (RFC 5007, 5460)
enum DHCPV6_lease_query_type {
    LQ6QT_BY_ADDRESS		= 1, 
    LQ6QT_BY_CLIENTID		= 2,
    LQ6QT_BY_RELAY_ID		= 3,
    LQ6QT_BY_LINK_ADDRESS	= 4,
    LQ6QT_BY_REMOTE_ID		= 5
};

enum DHCPV6_IA_type {
    IA_ADDRESS	= 5,
};

# RFC 3315 - DHCP Messages sent between clients and servers
#
#  0                   1                   2                   3
#  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |    msg-type   |               transaction-id                  |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                                                               |
# .                            options                            .
# .                           (variable)                          .
# |                                                               |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#
#
# RFC 3315 - Relay Agent/Server Message Formats
#  0                   1                   2                   3
#  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |    msg-type   |   hop-count   |                               |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               |
# |                                                               |
# |                         link-address                          |
# |                                                               |
# |                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-|
# |                               |                               |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               |
# |                                                               |
# |                         peer-address                          |
# |                                                               |
# |                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-|
# |                               |                               |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               |
# .                                                               .
# .            options (variable number and length)   ....        .
# |                                                               |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#
#

type dhcpv6_packet_option_duid_llt(len: uint16) = record {
    hwtype				: uint16;
    time				: uint32;
    lladdr				: bytestring &length=len-6;
};

type dhcpv6_packet_option_duid_en(len: uint16) = record {
    entnum				: uint32;
    identifier			: bytestring &length=len-4;
};

type dhcpv6_packet_option_duid_ll(len: uint16) = record {
    hwtype				: uint16;
    lladdr				: bytestring &length=len-2;
};

type dhcpv6_packet_option_duid_uuid(len: uint16) = record {
    hwtype				: uint16;
    lladdr				: uint128;
};
    
type dhcpv6_packet_option_client_id = record {
    len					: uint16;
    msgtype				: uint16;
    option				: case msgtype of {
        DUID_LLT 	 	-> duid_llt 	: dhcpv6_packet_option_duid_llt(len-2); # len-2 is accounting for the msgtype in the lower structure
        DUID_EN			-> duid_en		: dhcpv6_packet_option_duid_en(len-2);
        DUID_LL			-> duid_ll		: dhcpv6_packet_option_duid_ll(len-2);
        DUID_UUID		-> duid_uuid	: dhcpv6_packet_option_duid_uuid(len-2);
    };
};

type dhcpv6_packet_option_server_id = record {
    len					: uint16;
    msgtype				: uint16;
    option				: case msgtype of {
        DUID_LLT 	 	-> duid_llt 	: dhcpv6_packet_option_duid_llt(len-2); # len-2 is accounting for the msgtype in the lower structure
        DUID_EN			-> duid_en		: dhcpv6_packet_option_duid_en(len-2);
        DUID_LL			-> duid_ll		: dhcpv6_packet_option_duid_ll(len-2);
        DUID_UUID		-> duid_uuid	: dhcpv6_packet_option_duid_uuid(len-2);
    };
};

type dhcpv6_packet_option_ia_na_data = record {
    msgtype				: uint16;
    option				: case msgtype of {
         IA_ADDRESS		-> ia_addr		: dhcpv6_packet_option_iaaddr;
         default			-> skip			: bytestring &restofdata;
     };
};

type dhcpv6_packet_option_ia_na = record {
    len					: uint16;
    iaid				: uint32;
    t1					: uint32;
    t2				    : uint32;
    data				: bytestring &length=len-12;
} &let {
    option				: dhcpv6_packet_option_ia_na_data withinput data &if(len > 12);
};

type dhcpv6_packet_option_ia_ta = record {
    len					: uint16;
    iaid				: uint32;
    data				: bytestring &length=len-4;	
};

type dhcpv6_packet_option_iaaddr = record {
    len					: uint16;
    ipv6_addr			: uint128;
    preferred_lifetime	: uint32;
    valid_lifetime		: uint32;
    data				: bytestring &length=len-24;
};

type dhcpv6_packet_option_oro = record {
    len					: uint16 &check((len % 2) == 0);
    options				: uint16[opt_len] &check(opt_len >= 1);
} &let {
    opt_len = len/2 &if(len >= 2);
};

type dhcpv6_packet_option_preference = record {
    len					: uint16 &check(len == 1);
    pref_value			: uint8;
};

type dhcpv6_packet_option_elapsed_time = record {
    len					: uint16;
    elapsed_time		: uint16; # This time is expressed in hundredths of a second (10^-2 seconds).
};

type dhcpv6_packet_option_auth = record {
    len					: uint16;
    protocol			: uint8;
    algorithm			: uint8;
    rdm					: uint8;
    replay_detection	: uint64;
    auth_info			: bytestring &length=len-11;
};

type dhcpv6_packet_option_unicast = record {
    len					: uint16 &check(len == 16);
    server_address		: uint8;
};

type dhcpv6_packet_option_status_code = record {
    len					: uint16;
    status_code			: uint16;
    status_msg			: bytestring &length=len-2;
};

type dhcpv6_packet_option_rapid_commit = record {
    len					: uint16 &check(len == 0);
};

type dhcpv6_packet_option_user_class = record {
    len					: uint16;
    user_class_data		: bytestring &length=len;
};

type dhcpv6_packet_option_vendor_class = record {
    len						: uint16;
    enterprise_number		: uint32;
    vendor_class_data_len	: uint16;
    vendor_class_data		: bytestring &length=vendor_class_data_len;
};

type dhcpv6_packet_option_vendor_opts = record {
    len					: uint16;
    enterprise_number	: uint32;
    option_data			: bytestring &length=len-4;
};

type dhcpv6_packet_option_reconf_msg = record {
    len					: uint16 &check(len == 1);
    msg_type			: uint8 &check(msg_type == DHCPV6_RENEW || msg_type == DHCPV6_INFORMATION_REQUEST);
};

type dhcpv6_packet_option_reconf_accept = record {
    len					: uint16 &check(len == 0);
};

type dhcpv6_packet_option_sip_servers_dns = record {
    len							: uint16;
    sip_server_domain_name_list	: bytestring &length=len;
}

type dhcpv6_packet_option_sip_servers_addr = record {
    len							: uint16 &check((len%16) == 0);
    sip_server_domain_name_list	: bytestring &length=len;
}

type dhcpv6_packet_option_dns_servers = record {
    len					: uint16 &check((len%16) == 0);
    dns_name_servers	: uint128[name_server_len] &check(name_server_len >= 1);
} &let {
    name_server_len = len/16 &if(len >= 16);
};

type dhcpv6_packet_option_domain_list_searchlist = record {
    len					: uint8;
    entry				: bytestring &length=len;
};

type dhcpv6_packet_option_domain_list = record {
    len					: uint16;
    searchlist			: dhcpv6_packet_option_domain_list_searchlist[] &until($element == 0);
};

type dhcpv6_packet_option_ia_pd_option_iaprefix = record {
    len					: uint16;
    preferred_lifetime	: uint32;
    valid_lifetime		: uint32;
    prefix_length		: uint8;
    ipv6_prefix			: uint128;	
};

type dhcpv6_packet_option_ia_pd_data = record {
    msgtype			: uint16;
    option			: case msgtype of {
        DHCPV6_OPTION_IAPREFIX		-> iaprefix		: dhcpv6_packet_option_ia_pd_option_iaprefix;
    };
};

type dhcpv6_packet_option_ia_pd = record {
    len					: uint16;
    iaid				: uint32;
    t1					: uint32;
    t2					: uint32;
    data				: bytestring &length=len-12;
} &let {
    option				: dhcpv6_packet_option_ia_pd_data withinput data &if(len > 12);
};
type dhcpv6_packet_option_info_refresh_time = record {
    len					: uint16;
    refresh_time		: uint32;
};

type dhcpv6_packet_option_client_fqdn = record {
    len					: uint16;
    flags				: uint8;
    name				: bytestring &length=len-3;
};

type DHCPV6_packet_option = record {
    option_code			: uint16;
    option				: case option_code of {
        DHCPV6_OPTION_CLIENTID 	 				-> clientid 		: dhcpv6_packet_option_client_id;
        DHCPV6_OPTION_SERVERID 	 				-> serverid 		: dhcpv6_packet_option_server_id;
        DHCPV6_OPTION_IA_NA		 				-> ia_na	 		: dhcpv6_packet_option_ia_na; 
        DHCPV6_OPTION_IA_TA		 				-> ia_ta	 		: dhcpv6_packet_option_ia_ta;
        DHCPV6_OPTION_IAADDR	 				-> iaaddr	 		: dhcpv6_packet_option_iaaddr;
        DHCPV6_OPTION_ORO		 				-> oro		 		: dhcpv6_packet_option_oro;
        DHCPV6_OPTION_PREFERENCE 				-> pref	 			: dhcpv6_packet_option_preference;
        DHCPV6_OPTION_ELAPSED_TIME 				-> elapsed_time 	: dhcpv6_packet_option_elapsed_time;
        DHCPV6_OPTION_AUTH		 				-> auth				: dhcpv6_packet_option_auth;
        DHCPV6_OPTION_UNICAST					-> unicast			: dhcpv6_packet_option_unicast;
        DHCPV6_OPTION_STATUS_CODE  				-> status_code  	: dhcpv6_packet_option_status_code;
        DHCPV6_OPTION_RAPID_COMMIT				-> rapid_commit 	: dhcpv6_packet_option_rapid_commit;
        DHCPV6_OPTION_USER_CLASS				-> user_class		: dhcpv6_packet_option_user_class;
        DHCPV6_OPTION_VENDOR_CLASS				-> vendor_class		: dhcpv6_packet_option_vendor_class;
        DHCPV6_OPTION_VENDOR_OPTS				-> vendor_opts		: dhcpv6_packet_option_vendor_opts;
        DHCPV6_OPTION_RECONF_MSG				-> reconf_msg 		: dhcpv6_packet_option_reconf_msg;
        DHCPV6_OPTION_RECONF_ACCEPT				-> reconf_accept 	: dhcpv6_packet_option_reconf_accept;
        DHCPV6_OPTION_SIP_SERVERS_DNS			-> sip_servers_dns	: dhcpv6_packet_option_sip_servers_dns;
        DHCPV6_OPTION_SIP_SERVERS_ADDR			-> sip_servers_addr	: dhcpv6_packet_option_sip_servers_addr;
        DHCPV6_OPTION_NAME_SERVERS				-> name_servers		: dhcpv6_packet_option_dns_servers;
        DHCPV6_OPTION_DOMAIN_LIST				-> domain_list		: dhcpv6_packet_option_domain_list;
        DHCPV6_OPTION_IA_PD						-> ia_pd			: dhcpv6_packet_option_ia_pd;
        DHCPV6_OPTION_INFORMATION_REFRESH_TIME	-> inforefreshtime	: dhcpv6_packet_option_info_refresh_time;
        DHCPV6_OPTION_CLIENT_FQDN				-> client_fqdn		: dhcpv6_packet_option_client_fqdn;
        #default 								-> skip 			: bytestring &transient &restofdata;
    };
};

type dhcpv6_relay_packet_option_relay_msg = record {
    len					: uint16;
    data				: bytestring &length=len;
};

type dhcpv6_relay_packet_option_interface_id = record {
    len					: uint16;
    interface_id		: bytestring &length=len;
};

type DHCPV6_relay_packet_option = record {
    option_code	 		: uint16;
    option      	 	: case option_code of {
        DHCPV6_OPTION_RELAY_MSG		->	relay_msg : dhcpv6_relay_packet_option_relay_msg;
        DHCPV6_OPTION_INTERFACE_ID	->	intf_id   : dhcpv6_relay_packet_option_interface_id;
    };
};

type dhcpv6_relay_packet = record {
    hop_count	 		: uint8;
    link_address 		: uint16;
    peer_address 		: uint16;
    options				: DHCPV6_relay_packet_option[] &until($input.length() == 0);
};

type dhcpv4_over_dhcpv6_packet = record {
    flags				: uint24;
    option_code			: uint16;
    option_len			: uint16 &check((option_len%16) == 0);
    options				: bytestring &length=option_len;
};

type dhcvp6_packet = record {
    transaction_id_24  	: uint24;
    options				: DHCPV6_packet_option[] &until($input.length() == 0);
} &let {
    transaction_id : uint32 = to_int(transaction_id_24);
};

type DHCPV6_Message = record {
    msg_type			: uint8;
    body        		: case msg_type of {
        DHCPV6_SOLICIT				-> dhcpv6_solicit_msg     : dhcvp6_packet;
        DHCPV6_ADVERTISE			-> dhcpv6_advertise_msg   : dhcvp6_packet;
        DHCPV6_REQUEST				-> dhcpv6_request_msg 	  : dhcvp6_packet;
        DHCPV6_CONFIRM				-> dhcpv6_confirm_msg 	  : dhcvp6_packet;
        DHCPV6_RENEW				-> dhcpv6_renew_msg 	  : dhcvp6_packet;
        DHCPV6_REBIND				-> dhcpv6_rebind_msg	  : dhcvp6_packet;
        DHCPV6_REPLY				-> dhcpv6_reply_msg 	  : dhcvp6_packet;
        DHCPV6_RELEASE				-> dhcpv6_release_msg 	  : dhcvp6_packet;
        DHCPV6_DECLINE				-> dhcpv6_decline_msg 	  : dhcvp6_packet;
        DHCPV6_RECONFIGURE 			-> dhcpv6_reconfigure_msg : dhcvp6_packet;
        DHCPV6_INFORMATION_REQUEST 	-> dhcpv6_info_req_msg    : dhcvp6_packet;
        DHCPV6_RELAY_FORW 			-> dhcpv6_relay_forw_msg  : dhcpv6_relay_packet;
        DHCPV6_RELAY_REPL 			-> dhcpv6_relay_repl_msg  : dhcpv6_relay_packet;
        DHCPV6_DHCPV4_QUERY	   		-> dhcpv6_dhcpv4_query    : dhcpv4_over_dhcpv6_packet;
        DHCPV6_DHCPV4_RESPONSE		-> dhcpv6_dhcpv4_response : dhcpv4_over_dhcpv6_packet;
        default 					-> skip 				  : bytestring &transient &restofdata;
    };
} &byteorder = bigendian;
