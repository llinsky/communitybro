# Definitions for DCE RPC.

enum dce_rpc_ptype {
	DCE_RPC_REQUEST,
	DCE_RPC_PING,
	DCE_RPC_RESPONSE,
	DCE_RPC_FAULT,
	DCE_RPC_WORKING,
	DCE_RPC_NOCALL,
	DCE_RPC_REJECT,
	DCE_RPC_ACK,
	DCE_RPC_CL_CANCEL,
	DCE_RPC_FACK,
	DCE_RPC_CANCEL_ACK,
	DCE_RPC_BIND,
	DCE_RPC_BIND_ACK,
	DCE_RPC_BIND_NAK,
	DCE_RPC_ALTER_CONTEXT,
	DCE_RPC_ALTER_CONTEXT_RESP,
	DCE_RPC_SHUTDOWN,
	DCE_RPC_CO_CANCEL,
	DCE_RPC_ORPHANED,
};

enum dce_rpc_lsa_type {
	DCE_RPC_LSA_CLOSE 							= 0x00,
	DCE_RPC_LSA_FUNCTION_0x01 					= 0x01,
	DCE_RPC_LSA_ENUM_PRIVILEGES 				= 0x02,
	DCE_RPC_LSA_QUERY_SECURITY 					= 0x03,
	DCE_RPC_LSA_SET_SECURITY 					= 0x04,
	DCE_RPC_LSA_FUNCTION_0x05					= 0x05,
	DCE_RPC_LSA_FUNCTION_0x06 					= 0x06,
	DCE_RPC_LSA_QUERY_INFO_POLICY 				= 0x07,
	DCE_RPC_LSA_FUNCTION_0x08 					= 0x08,
	DCE_RPC_LSA_FUNCTION_0x09 					= 0x09,
	DCE_RPC_LSA_CREATE_ACCOUNT 					= 0x0A,
	DCE_RPC_LSA_ENUM_ACCOUNT 					= 0x0B,
	DCE_RPC_LSA_FUNCTION_0x0C 					= 0x0C,
	DCE_RPC_LSA_FUNCTION_0x0D 					= 0x0D,
	DCE_RPC_LSA_LOOKUP_NAMES 					= 0x0E,
	DCE_RPC_LSA_LOOKUP_SIDS 					= 0x0F,
	DCE_RPC_LSA_FUNCTION_0x10 					= 0x10,
	DCE_RPC_LSA_OPEN_ACCOUNT 					= 0x11,
	DCE_RPC_LSA_ENUM_PRIVILEGES_ACCOUNT 		= 0x12,
	DCE_RPC_LSA_ADD_PRIVILEGES_TO_ACCOUNT 		= 0x13,
	DCE_RPC_LSA_REMOVE_PRIVILEGES_FROM_ACCOUNT 	= 0x14,
	DCE_RPC_LSA_FUNCTION_0x15					= 0x15,
	DCE_RPC_LSA_FUNCTION_0x16 					= 0x16,
	DCE_RPC_LSA_GET_SYSTEM_ACCESS_ACCOUNT	 	= 0x17,
	DCE_RPC_LSA_SET_SYSTEM_ACCESS_ACCOUNT		= 0x18,
	DCE_RPC_LSA_FUNCTION_0x19					= 0x19,
	DCE_RPC_LSA_FUNCTION_0x1A 					= 0x1A,
	DCE_RPC_LSA_FUNCTION_0x1B					= 0x1B,
	DCE_RPC_LSA_FUNCTION_0x1C 					= 0x1C,
	DCE_RPC_LSA_FUNCTION_0x1D					= 0x1D,
	DCE_RPC_LSA_FUNCTION_0x1E 					= 0x1E,
	DCE_RPC_LSA_LOOKUP_PRIVILEGE_VALUE			= 0x1F,
	DCE_RPC_LSA_LOOKUP_PRIVILEGE_NAME			= 0x20,
	DCE_RPC_LSA_LOOKUP_PRIVILEGE_DISPLAY_NAME	= 0x21,
	DCE_RPC_LSA_DELETE_OBJECT					= 0x22,
	DCE_RPC_LSA_ENUM_ACCOUNTS_WITH_USER_RIGHT	= 0x23,
	DCE_RPC_LSA_ENUM_ACCOUNT_RIGHTS				= 0x24,
	DCE_RPC_LSA_ADD_ACCOUNT_RIGHTS				= 0x25,
	DCE_RPC_LSA_REMOVE_ACCOUNT_RIGHTS			= 0x26,
	DCE_RPC_LSA_FUNCTION_0x27					= 0x27,
	DCE_RPC_LSA_FUNCTION_0x28 					= 0x28,
	DCE_RPC_LSA_FUNCTION_0x29					= 0x29,
	DCE_RPC_LSA_FUNCTION_0x2A 					= 0x2A,
	DCE_RPC_LSA_FUNCTION_0x2B					= 0x2B,
	DCE_RPC_LSA_OPEN_POLICY2					= 0x2C,
	DCE_RPC_LSA_GETUSERNAME						= 0x2D,	
	DCE_RPC_LSA_QUERY_INFO_POLICY2				= 0x2E,
	DCE_RPC_LSA_FUNCTION_0x2F					= 0x2F,
	DCE_RPC_LSA_FUNCTION_0x30 					= 0x30,
	DCE_RPC_LSA_FUNCTION_0x31					= 0x31,
	DCE_RPC_LSA_FUNCTION_0x32 					= 0x32,
	DCE_RPC_LSA_FUNCTION_0x33					= 0x33,
	DCE_RPC_LSA_FUNCTION_0x34 					= 0x34,
	DCE_RPC_LSA_FUNCTION_0x35 					= 0x35,
	DCE_RPC_LSA_FUNCTION_0x36					= 0x36,
	DCE_RPC_LSA_FUNCTION_0x37 					= 0x37,
	DCE_RPC_LSA_FUNCTION_0x38					= 0x38,
	DCE_RPC_LSA_LOOKUP_SIDS2					= 0x39,
	DCE_RPC_LSA_LOOKUP_NAMES2					= 0x3A,
	DCE_RPC_LSA_FUNCTION_0x3B					= 0x3B,
	DCE_RPC_LSA_FUNCTION_0x3C 					= 0x3C,
	DCE_RPC_LSA_FUNCTION_0x3D					= 0x3D,
	DCE_RPC_LSA_FUNCTION_0x3E 					= 0x3E,
	DCE_RPC_LSA_FUNCTION_0x3F 					= 0x3F,
	DCE_RPC_LSA_FUNCTION_0x40					= 0x40,
	DCE_RPC_LSA_FUNCTION_0x41 					= 0x41,
	DCE_RPC_LSA_FUNCTION_0x42					= 0x42,
	DCE_RPC_LSA_FUNCTION_0x43					= 0x43,
	DCE_RPC_LSA_LOOKUP_NAMES3					= 0x44,
};

enum dce_rpc_lsa_policy_info {
	LSA_POLICY_INFO_AUDIT_LOG,
	LSA_POLICY_INFO_AUDIT_EVENTS,
	LSA_POLICY_INFO_DOMAIN,
	LSA_POLICY_INFO_PD,
	LSA_POLICY_INFO_ACCOUNT_DOMAIN,
	LSA_POLICY_INFO_ROLE,
	LSA_POLICY_INFO_REPLICA,
	LSA_POLICY_INFO_QUOTA,
	LSA_POLICY_INFO_DB,
	LSA_POLICY_INFO_AUDIT_FULL_SET,
	LSA_POLICY_INFO_AUDIT_FULL_QUERY,
	LSA_POLICY_INFO_DNS,
	LSA_POLICY_INFO_DNS_INT,
	LSA_POLICY_INFO_LOCAL_ACCOUNT_DOMAIN,
};

type uuid = bytestring &length = 16;

type context_handle = record {
	attrs : uint32;
	uuid  : bytestring &length = 16;
};

type DCE_RPC_PDU(is_orig: bool) = record {
	header  : DCE_RPC_Header(is_orig);
	frag    : bytestring &length=body_length &check(body_length > 0);
	auth    : DCE_RPC_Auth_wrapper(header);
} &let {
	# Subtract an extra 8 when there is an auth section because we have some "auth header" fields in that structure.
	body_length      : uint32 = header.frag_length - sizeof(header) - header.auth_length - (header.auth_length > 0 ? 8 : 0);
	frag_reassembled : bool = $context.flow.reassemble_fragment(header, frag);
	body             : DCE_RPC_Body(header) withinput $context.flow.reassembled_body(header, frag) &if(frag_reassembled);
} &byteorder = header.byteorder, &length = header.frag_length;

type NDR_Format = record {
	intchar    : uint8;
	floatspec  : uint8;
	reserved   : padding[2];
} &let {
	byteorder = (intchar >> 4) ? littleendian : bigendian;
};

type DCE_RPC_Header(is_orig: bool) = record {
	rpc_vers       : uint8 &check(rpc_vers == 5);
	rpc_vers_minor : uint8;
	PTYPE          : uint8;
	pfc_flags      : uint8;
	packed_drep    : NDR_Format;
	frag_length    : uint16;
	auth_length    : uint16;
	call_id        : uint32;
} &let {
	firstfrag = pfc_flags & 1;
	lastfrag  = (pfc_flags >> 1) & 1;
	object    = (pfc_flags >> 7) & 1;
} &byteorder = packed_drep.byteorder;

type Syntax = record {
	uuid      : bytestring &length = 16;
	ver_major : uint16;
	ver_minor : uint16;
};

type ContextRequest = record {
	id                : uint16;
	num_syntaxes      : uint8;
	reserved          : padding[1];
	abstract_syntax   : Syntax;
	transfer_syntaxes : Syntax[num_syntaxes];
};

type ContextReply = record {
	ack_result        : uint16;
	ack_reason        : uint16;
	syntax            : Syntax;
};

type ContextList(is_request: bool) = record {
	num_contexts   : uint8;
	reserved       : padding[3];
	req_reply      : case is_request of {
		true  -> request_contexts : ContextRequest[num_contexts];
		false -> reply_contexts   : ContextReply[num_contexts];
	};
};

type DCE_RPC_Bind = record {
	max_xmit_frag  : uint16;
	max_recv_frag  : uint16;
	assoc_group_id : uint32;
	context_list   : ContextList(1);
};

type DCE_RPC_Bind_Ack = record {
	max_xmit_frag   : uint16;
	max_recv_frag   : uint16;
	assoc_group_id  : uint32;
	sec_addr_length : uint16;
	sec_addr        : bytestring &length=sec_addr_length;
	num_results		: uint8;
	pad             : padding align 4;
	contexts        : ContextList(0)[num_results];
};

type lsa_policy_handle = record {
	handle			: bytestring &length=20;
};

type lsa_string = record {
	ref_id			: uint32;
	max_count		: uint32;
	offset			: uint32;
	actual_count	: uint32;
	value			: uint8[value_len] &requires(value_len);
} &let {
	value_len		: uint32 = (actual_count*2) + 2;
	total_len		: uint32 = value_len + 16;
};

type lsa_account_name = record {
	length			: uint16;
	size			: uint16;
	ptr_to_string	: lsa_string;
} &let {
	total_len		: uint32 = ptr_to_string.total_len + 4;
};

type lsa_ptr_account_name = record {
	refid			: uint32;
	account_name	: lsa_account_name;
} &let {
	total_len		: uint32 = account_name.total_len + 4;
};

type lsa_ptr_authority_name(len: uint32) = record {
	authority_name	: bytestring &length=len + 2;
};

type lsa_sid = record {
	refid			: uint32;
	count			: uint32;
	revision		: uint8;
	num_auth		: uint8;
	authority		: bytestring &length=6;
	subauthorities	: bytestring &length=20;
	rid				: uint32;		
};

type lsa_sid_ptr = record {
	refid			: uint32;
	max_count		: uint32;
	sids			: lsa_sid[max_count];
};

type lsa_sid_array = record {
	num_of_sids		: uint32;
	ptr_to_sids		: lsa_sid_ptr[num_of_sids];	
};

type lsa_ptr_object_attribute = record {
	len				: uint32;
	ptr_root_dir	: uint8;
	ptr_obj_name	: uint16;
	attribute		: uint32;
	ptr_sec_desc	: uint32;
	ptr_sec_qos		: uint32;	
};

type dce_rpc_lsa_open_policy2_request = record {
	ptr_sys_name	: lsa_string;
	ptr_obj_attr	: lsa_ptr_object_attribute;
	access_mask		: uint32;
};

type dce_rpc_lsa_query_info_policy_request = record {
	handle			: lsa_policy_handle;
	level			: uint8;		# enum dce_rpc_lsa_policy_info
};

type dce_rpc_lsa_close_request = record {
	handle			: lsa_policy_handle;
};

type dce_rpc_lsa_lookup_sids_request = record {
	policy_handle	: lsa_policy_handle;
	ptr_sids		: lsa_sid_array;
};

type dce_rpc_lsa_getusername_request(alloc_hint: uint32) = record {
	system_name				: lsa_string;
	ptr_account_name		: lsa_ptr_account_name;
	ptr_authority_name		: bytestring &length=ptr_authority_name_len &requires(ptr_authority_name_len);
} &let {
	system_name_len      	: uint32 = system_name.total_len; 
	ptr_account_name_len 	: uint32 = ptr_account_name.total_len;
	ptr_authority_name_len	: uint32 = alloc_hint-(system_name_len+ptr_account_name_len);
};

type DCE_RPC_STUB_REQUEST(opnum: uint16, context_id: uint16, alloc_hint: uint32) = case opnum of {
	DCE_RPC_LSA_OPEN_POLICY2		->	lsa_open_policy2		:	dce_rpc_lsa_open_policy2_request;
	DCE_RPC_LSA_QUERY_INFO_POLICY	->	lsa_query_info_policy	:	dce_rpc_lsa_query_info_policy_request;
	DCE_RPC_LSA_CLOSE				->	lsa_close				:	dce_rpc_lsa_close_request;
	DCE_RPC_LSA_LOOKUP_SIDS			->	lsa_lookup_sids			:	dce_rpc_lsa_lookup_sids_request;
	DCE_RPC_LSA_GETUSERNAME			->  lsa_getusername			:	dce_rpc_lsa_getusername_request(alloc_hint);
	default							->  skip					: 	bytestring	&length=alloc_hint;
};

type DCE_RPC_Request(h: DCE_RPC_Header) = record {
	alloc_hint   : uint32;
	context_id   : uint16;
	opnum        : uint16;
	has_object   : case h.object of {
		true  -> uuid    : uuid;
		false -> no_uuid : empty;
	};
	stub_pad     : padding align 8;
	stub         : bytestring &length=alloc_hint;
} &let {
	stub_value	 : DCE_RPC_STUB_REQUEST(opnum, context_id, alloc_hint) withinput stub &if(alloc_hint > 0);
};	

type DCE_RPC_Response = record {
	alloc_hint   : uint32;
	context_id   : uint16;
	cancel_count : uint8;
	reserved     : uint8;
	stub_pad     : padding align 8;
	stub         : bytestring &length=alloc_hint;
};

type DCE_RPC_AlterContext = record {
	max_xmit_frag  : uint16;
	max_recv_frag  : uint16;
	assoc_group_id : uint32;
	contexts       : ContextList(0);
};

type DCE_RPC_AlterContext_Resp = record {
	max_xmit_frag  : uint16;
	max_recv_frag  : uint16;
	assoc_group_id : uint32;
	sec_addr_len   : uint16;
	contexts       : ContextList(0);
};

type DCE_RPC_Body(header: DCE_RPC_Header) = case header.PTYPE of {
	DCE_RPC_BIND               -> bind          : DCE_RPC_Bind;
	DCE_RPC_BIND_ACK           -> bind_ack      : DCE_RPC_Bind_Ack;
	DCE_RPC_REQUEST            -> request       : DCE_RPC_Request(header);
	DCE_RPC_RESPONSE           -> response      : DCE_RPC_Response;
	# TODO: Something about the two following structures isn't being handled correctly.
	#DCE_RPC_ALTER_CONTEXT      -> alter_context : DCE_RPC_AlterContext;
	#DCE_RPC_ALTER_CONTEXT_RESP -> alter_resp    : DCE_RPC_AlterContext_Resp;
	default                    -> other         : bytestring &restofdata;
};

type DCE_RPC_Auth_wrapper(header: DCE_RPC_Header) = case header.auth_length of {
	0       -> none : empty;
	default -> auth : DCE_RPC_Auth(header);
};

type DCE_RPC_Auth(header: DCE_RPC_Header) = record {
	type       : uint8;
	level      : uint8;
	pad_len    : uint8;
	reserved   : uint8;
	context_id : uint32;
	blob       : bytestring &length=header.auth_length;
};

flow DCE_RPC_Flow(is_orig: bool) {
	flowunit = DCE_RPC_PDU(is_orig) withcontext(connection, this);

	%member{
		std::map<uint32, std::unique_ptr<FlowBuffer>> fb;
	%}

	# Fragment reassembly.
	function reassemble_fragment(header: DCE_RPC_Header, frag: bytestring): bool
		%{
		if ( ${header.firstfrag} )
			{
			if ( fb.count(${header.call_id}) > 0 )
				{
				// We already had a first frag earlier.
				reporter->Weird(connection()->bro_analyzer()->Conn(),
						"multiple_first_fragments_in_dce_rpc_reassembly");
				connection()->bro_analyzer()->SetSkip(true);
				return false;
				}

			if ( ${header.lastfrag} )
				{
				// all-in-one packet
				return true;
				}
			else
				{
				// first frag, but not last so we start a flowbuffer
				fb[${header.call_id}] = std::unique_ptr<FlowBuffer>(new FlowBuffer());
				fb[${header.call_id}]->NewFrame(0, true);
				fb[${header.call_id}]->BufferData(frag.begin(), frag.end());

				if ( fb.size() > BifConst::DCE_RPC::max_cmd_reassembly )
					{
					reporter->Weird(connection()->bro_analyzer()->Conn(),
					                "too_many_dce_rpc_msgs_in_reassembly");
					connection()->bro_analyzer()->SetSkip(true);
					}

				if ( fb[${header.call_id}]->data_length() > (int)BifConst::DCE_RPC::max_frag_data )
					{
					reporter->Weird(connection()->bro_analyzer()->Conn(),
					                "too_much_dce_rpc_fragment_data");
					connection()->bro_analyzer()->SetSkip(true);
					}

				return false;
				}
			}
		else if ( fb.count(${header.call_id}) > 0 )
			{
			// not the first frag, but we have a flow buffer so add to it
			fb[${header.call_id}]->BufferData(frag.begin(), frag.end());

			if ( fb[${header.call_id}]->data_length() > (int)BifConst::DCE_RPC::max_frag_data )
				{
				reporter->Weird(connection()->bro_analyzer()->Conn(),
				                "too_much_dce_rpc_fragment_data");
				connection()->bro_analyzer()->SetSkip(true);
				}

			return ${header.lastfrag};
			}
		else
			{
			// no flow buffer and not a first frag, ignore it.
			return false;
			}

		// can't reach here.
		return false;
		%}

	function reassembled_body(h: DCE_RPC_Header, body: bytestring): const_bytestring
		%{
		const_bytestring bd = body;

		if ( fb.count(${h.call_id}) > 0 )
			{
			bd = const_bytestring(fb[${h.call_id}]->begin(), fb[${h.call_id}]->end());
			fb.erase(${h.call_id});
			}

		return bd;
		%}
};
