
refine connection DCE_RPC_Conn += {
	%member{
		map<uint16, uint16> cont_id_opnum_map;
		uint64 fid;
	%}

	%init{
		fid = 0;
	%}
	
	
	function uint8s_to_stringval(data: uint8[]): StringVal
	%{
		int length = data->size();
		uint8 buf[length];
	
		for ( int i = 0; i < length; ++i) {
			buf[i] = (*data)[i];
		}
	
		const bytestring bs = bytestring(buf, length);
		return utf16_bytestring_to_utf8_val(bro_analyzer()->Conn(), bs);
	%}


	function set_file_id(fid_in: uint64): bool
		%{
		fid = fid_in;
		return true;
		%}

	function get_cont_id_opnum_map(cont_id: uint16): uint16
		%{
		return cont_id_opnum_map[cont_id];
		%}

	function set_cont_id_opnum_map(cont_id: uint16, opnum: uint16): bool
		%{
		cont_id_opnum_map[cont_id] = opnum;
		return true;
		%}

	function proc_dce_rpc_pdu(pdu: DCE_RPC_PDU): bool
	%{
		// If a whole pdu message parsed ok, let's confirm the protocol
		bro_analyzer()->ProtocolConfirmation();
		return true;
	%}

	function proc_dce_rpc_message(header: DCE_RPC_Header): bool
		%{
		if ( dce_rpc_message )
			{
			BifEvent::generate_dce_rpc_message(bro_analyzer(),
			                                   bro_analyzer()->Conn(),
			                                   ${header.is_orig},
			                                   fid,
			                                   ${header.PTYPE},
			                                   new EnumVal(${header.PTYPE}, BifType::Enum::DCE_RPC::PType));
			}
		return true;
		%}

	function process_dce_rpc_bind(req: ContextRequest): bool
		%{
		if ( dce_rpc_bind )
			{
			BifEvent::generate_dce_rpc_bind(bro_analyzer(),
			                                bro_analyzer()->Conn(),
			                                fid,
			                                bytestring_to_val(${req.abstract_syntax.uuid}),
			                                ${req.abstract_syntax.ver_major},
			                                ${req.abstract_syntax.ver_minor});
			}

		return true;
		%}

	function process_dce_rpc_bind_ack(bind: DCE_RPC_Bind_Ack): bool
		%{
		if ( dce_rpc_bind_ack )
			{
			StringVal *sec_addr;
			// Remove the null from the end of the string if it's there.
			if ( ${bind.sec_addr}.length() > 0 &&
			     *(${bind.sec_addr}.begin() + ${bind.sec_addr}.length()) == 0 )
				{
				sec_addr = new StringVal(${bind.sec_addr}.length()-1, (const char*) ${bind.sec_addr}.begin());
				}
			else
				{
				sec_addr = new StringVal(${bind.sec_addr}.length(), (const char*) ${bind.sec_addr}.begin());
				}

			BifEvent::generate_dce_rpc_bind_ack(bro_analyzer(),
			                                    bro_analyzer()->Conn(),
			                                    fid,
			                                    sec_addr);
			}
		return true;
		%}

	function process_dce_rpc_request(req: DCE_RPC_Request): bool
	%{
		if ( dce_rpc_request ) {
		     if ( ${req.stub}.length() > 0 ) {		     	
		     	switch ( ${req.opnum} ) {
		     		case DCE_RPC_LSA_GETUSERNAME: { 
		     			if ( ${req}->has_stub_value() > 0 ) {
			     			RecordVal* getusername_req = new RecordVal(BifType::Record::DCE_RPC::LSA_GETUSERNAME_REQUEST);
			     			
			     			RecordVal* system_name = new RecordVal(BifType::Record::DCE_RPC::DCE_LSA_STRING);
			     			system_name->Assign(0, new Val(${req.stub_value.lsa_getusername.system_name.ref_id}, TYPE_COUNT));
			     			system_name->Assign(1, new Val(${req.stub_value.lsa_getusername.system_name.max_count}, TYPE_COUNT));
			     			system_name->Assign(2, new Val(${req.stub_value.lsa_getusername.system_name.offset}, TYPE_COUNT));
			     			system_name->Assign(3, new Val(${req.stub_value.lsa_getusername.system_name.actual_count}, TYPE_COUNT));
			     			system_name->Assign(4, uint8s_to_stringval(${req.stub_value.lsa_getusername.system_name.value}));
			     			
			     			getusername_req->Assign(0, system_name);
			     			
			     			RecordVal* ptr_account_name = new RecordVal(BifType::Record::DCE_RPC::DCE_LSA_PTR_ACCOUNT_NAME);
			     			ptr_account_name->Assign(0, new Val(${req.stub_value.lsa_getusername.ptr_account_name.refid}, TYPE_COUNT));
			     			
			     			RecordVal* account_name = new RecordVal(BifType::Record::DCE_RPC::DCE_LSA_ACCOUNT_NAME);
			     			account_name->Assign(0, new Val(${req.stub_value.lsa_getusername.ptr_account_name.account_name.length}, TYPE_COUNT));
			     			account_name->Assign(1, new Val(${req.stub_value.lsa_getusername.ptr_account_name.account_name.size}, TYPE_COUNT));
			     			
			     			RecordVal* account_name_ptr = new RecordVal(BifType::Record::DCE_RPC::DCE_LSA_STRING);
			     			account_name_ptr->Assign(0, new Val(${req.stub_value.lsa_getusername.ptr_account_name.account_name.ptr_to_string.ref_id}, TYPE_COUNT));
			     			account_name_ptr->Assign(1, new Val(${req.stub_value.lsa_getusername.ptr_account_name.account_name.ptr_to_string.max_count}, TYPE_COUNT));
			     			account_name_ptr->Assign(2, new Val(${req.stub_value.lsa_getusername.ptr_account_name.account_name.ptr_to_string.offset}, TYPE_COUNT));
			     			account_name_ptr->Assign(3, new Val(${req.stub_value.lsa_getusername.ptr_account_name.account_name.ptr_to_string.actual_count}, TYPE_COUNT));
			     			account_name_ptr->Assign(4, uint8s_to_stringval(${req.stub_value.lsa_getusername.ptr_account_name.account_name.ptr_to_string.value}));
			     			
			     			account_name->Assign(2, account_name_ptr);
			     			
			     			ptr_account_name->Assign(1, account_name);
			     			
			     			getusername_req->Assign(1, ptr_account_name);
			     			//getusername_req->Assign(2, ToHex(std_str(${req.stub_value.lsa_getusername.ptr_authority_name}), false));
			     			
			     			BifEvent::generate_lsa_getusername_request(bro_analyzer(),
				                                   					  bro_analyzer()->Conn(),
				                                   					  getusername_req);
   					  	}
	     			}
	     			break;	
		     	}
		    }
		    
			BifEvent::generate_dce_rpc_request(bro_analyzer(),
			                                   bro_analyzer()->Conn(),
			                                   fid,
			                                   ${req.opnum},
			                                   ${req.stub}.length());
		}
	
		set_cont_id_opnum_map(${req.context_id},
		                      ${req.opnum});
		return true;
	%}

	function process_dce_rpc_response(resp: DCE_RPC_Response): bool
		%{
		if ( dce_rpc_response )
			{
			BifEvent::generate_dce_rpc_response(bro_analyzer(),
			                                    bro_analyzer()->Conn(),
			                                    fid,
			                                    get_cont_id_opnum_map(${resp.context_id}),
			                                    ${resp.stub}.length());
			}

		return true;
		%}

};

refine typeattr DCE_RPC_PDU += &let {
	proc = $context.connection.proc_dce_rpc_pdu(this);
}

refine typeattr DCE_RPC_Header += &let {
	proc = $context.connection.proc_dce_rpc_message(this);
};

refine typeattr ContextRequest += &let {
	proc = $context.connection.process_dce_rpc_bind(this);
};

refine typeattr DCE_RPC_Bind_Ack += &let {
	proc = $context.connection.process_dce_rpc_bind_ack(this);
};

refine typeattr DCE_RPC_Request += &let {
	proc = $context.connection.process_dce_rpc_request(this);
};

refine typeattr DCE_RPC_Response += &let {
	proc = $context.connection.process_dce_rpc_response(this);
};

