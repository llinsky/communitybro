connection DHCPV6_Conn(bro_analyzer: BroAnalyzer) {
	upflow   = DHCPV6_Flow(true);
	downflow = DHCPV6_Flow(false);
};

flow DHCPV6_Flow(is_orig: bool) {
	datagram = DHCPV6_Message withcontext(connection, this);
	
	%member{
		
	%}

	%init{
		
	%}

	%cleanup{
	
	%}
				
	function proc_dhcpv6_options(options: DHCPV6_packet_option[]): RecordVal 
	%{
		vector<DHCPV6_packet_option*>::const_iterator ptr;
		
		RecordVal* dhcpv6_po = new RecordVal(BifType::Record::DHCPV6::Options);
		for ( ptr = options->begin(); ptr != options->end(); ++ptr ) {
			switch( (*ptr)->option_code() ) {
			
				case DHCPV6_OPTION_CLIENTID: {
					RecordVal* option_clientid = new RecordVal(BifType::Record::DHCPV6::DHCPV6_OPTION_CLIENTID);					
					option_clientid->Assign(0, new Val((*ptr)->clientid()->msgtype(), TYPE_COUNT));
					
					switch((*ptr)->clientid()->msgtype()) {
						case DUID_LLT: {
							RecordVal* option_duid_llt = new RecordVal(BifType::Record::DHCPV6::DUID_LLT);
							option_duid_llt->Assign(0, new Val((*ptr)->clientid()->duid_llt()->hwtype(), TYPE_COUNT));
							option_duid_llt->Assign(1, new Val((*ptr)->clientid()->duid_llt()->time(), TYPE_COUNT));
							
							if ( (*ptr)->clientid()->duid_llt()->hwtype() == HTYPE_ETHER ) {
								option_duid_llt->Assign(2, EthAddrToStr((const u_char *)(std_str((*ptr)->clientid()->duid_llt()->lladdr()).c_str())));
							}
							
							option_clientid->Assign(1, option_duid_llt);
						}
							break;
							
						case DUID_EN: {
							RecordVal* option_duid_en = new RecordVal(BifType::Record::DHCPV6::DUID_EN);
							option_duid_en->Assign(0, new Val((*ptr)->clientid()->duid_en()->entnum(), TYPE_COUNT));
							option_duid_en->Assign(1, ToHex(std_str((*ptr)->clientid()->duid_en()->identifier()), false));
							
							option_clientid->Assign(2, option_duid_en);
						}
							break;
							
						case DUID_LL: {
							RecordVal* option_duid_ll = new RecordVal(BifType::Record::DHCPV6::DUID_LL);
							option_duid_ll->Assign(0, new Val((*ptr)->clientid()->duid_ll()->hwtype(), TYPE_COUNT));
							option_duid_ll->Assign(1, EthAddrToStr((const u_char *)(std_str((*ptr)->clientid()->duid_ll()->lladdr()).c_str())));
							
							if ( (*ptr)->clientid()->duid_ll()->hwtype() == HTYPE_ETHER ) {
								option_duid_ll->Assign(2, EthAddrToStr((const u_char *)(std_str((*ptr)->clientid()->duid_ll()->lladdr()).c_str())));
							}
							
							option_clientid->Assign(3, option_duid_ll);
						}
							break;
							
						case DUID_UUID: {
							std::cout << "DUID_UUID FOUND" << std::endl;
							// RecordVal* option_duid_uuid = new RecordVal(BifType::Record::DHCPV6::DUID_UUID);
							// option_duid_uuid->Assign(0, new Val((*ptr)->clientid()->duid_uuid()->hwtype(), TYPE_COUNT));
							// option_duid_uuid->Assign(1, ToHex(std_str((*ptr)->clientid()->duid_uuid()->lladdr()), false));
							
							// option_clientid->Assign(4, option_duid_uuid);
						}
							break;
						default: {
							connection()->bro_analyzer()->ProtocolViolation(fmt("Unknown DHCPV6 ClientID msgtype: %d", (*ptr)->clientid()->msgtype()));
							break;
						}
					}	
					
					dhcpv6_po->Assign(0, option_clientid);				 			
				}
					break;
					
				case DHCPV6_OPTION_SERVERID: {
					RecordVal* option_serverid = new RecordVal(BifType::Record::DHCPV6::DHCPV6_OPTION_SERVERID);					
					option_serverid->Assign(0, new Val((*ptr)->serverid()->msgtype(), TYPE_COUNT));
										
					switch((*ptr)->serverid()->msgtype()) {
						case DUID_LLT: {
							RecordVal* option_duid_llt = new RecordVal(BifType::Record::DHCPV6::DUID_LLT);
							option_duid_llt->Assign(0, new Val((*ptr)->serverid()->duid_llt()->hwtype(), TYPE_COUNT));
							option_duid_llt->Assign(1, new Val((*ptr)->serverid()->duid_llt()->time(), TYPE_COUNT));
							
							if ( (*ptr)->serverid()->duid_llt()->hwtype() == HTYPE_ETHER ) {
								option_duid_llt->Assign(2, EthAddrToStr((const u_char *)(std_str((*ptr)->serverid()->duid_llt()->lladdr()).c_str())));
							}
							
							option_serverid->Assign(1, option_duid_llt);
						}
							break;
							
						case DUID_EN: {
							RecordVal* option_duid_en = new RecordVal(BifType::Record::DHCPV6::DUID_EN);
							option_duid_en->Assign(0, new Val((*ptr)->serverid()->duid_en()->entnum(), TYPE_COUNT));
							option_duid_en->Assign(1, ToHex(std_str((*ptr)->serverid()->duid_en()->identifier()), false));
							
							option_serverid->Assign(2, option_duid_en);
						}
							break;
							
						case DUID_LL: {
							RecordVal* option_duid_ll = new RecordVal(BifType::Record::DHCPV6::DUID_LL);
							option_duid_ll->Assign(0, new Val((*ptr)->serverid()->duid_ll()->hwtype(), TYPE_COUNT));
							
							if ( (*ptr)->serverid()->duid_llt()->hwtype() == HTYPE_ETHER ) {
								option_duid_ll->Assign(2, EthAddrToStr((const u_char *)(std_str((*ptr)->serverid()->duid_ll()->lladdr()).c_str())));
							}
							
							option_serverid->Assign(3, option_duid_ll);
						}
							break;
							
						case DUID_UUID: {
							RecordVal* option_duid_uuid = new RecordVal(BifType::Record::DHCPV6::DUID_UUID);
							option_duid_uuid->Assign(0, new Val((*ptr)->serverid()->duid_uuid()->hwtype(), TYPE_COUNT));
							//option_duid_uuid->Assign(1, ToHex(std_str((*ptr)->serverid()->duid_uuid()->lladdr()), false));
							
							option_serverid->Assign(4, option_duid_uuid);
						}
							break;
						default: {
							connection()->bro_analyzer()->ProtocolViolation(fmt("Unknown DHCPV6 serverid msgtype: %d", (*ptr)->serverid()->msgtype()));
							break;
						}
					}	
					
					dhcpv6_po->Assign(1, option_serverid);				 			
				}
					break;
					
				case DHCPV6_OPTION_IA_NA: {
					RecordVal* option_ia_na = new RecordVal(BifType::Record::DHCPV6::DHCPV6_OPTION_IA_NA);					
					option_ia_na->Assign(0, new Val((*ptr)->ia_na()->iaid(), TYPE_COUNT));
					option_ia_na->Assign(1, new Val((*ptr)->ia_na()->t1(), TYPE_COUNT));
					option_ia_na->Assign(2, new Val((*ptr)->ia_na()->t2(), TYPE_COUNT));

					if ( (*ptr)->ia_na()->has_option() > 0 ) {
						switch((*ptr)->ia_na()->option()->msgtype()) {
							case IA_ADDRESS: { 
								RecordVal* option_iaaddr = new RecordVal(BifType::Record::DHCPV6::DHCPV6_OPTION_IAADDR);
								
								uint32 tmp_addr[4];
								tmp_addr[0] = htonl((*ptr)->ia_na()->option()->ia_addr()->ipv6_addr()->a1());
								tmp_addr[1] = htonl((*ptr)->ia_na()->option()->ia_addr()->ipv6_addr()->a2());
								tmp_addr[2] = htonl((*ptr)->ia_na()->option()->ia_addr()->ipv6_addr()->a3());
								tmp_addr[3] = htonl((*ptr)->ia_na()->option()->ia_addr()->ipv6_addr()->a4());
							
								option_iaaddr->Assign(0, new AddrVal(IPAddr(IPv6, (const uint32_t *)tmp_addr, IPAddr::Network)));
								option_iaaddr->Assign(1, new Val((*ptr)->ia_na()->option()->ia_addr()->preferred_lifetime(), TYPE_COUNT));
								option_iaaddr->Assign(2, new Val((*ptr)->ia_na()->option()->ia_addr()->valid_lifetime(), TYPE_COUNT));
										
								option_ia_na->Assign(3, option_iaaddr);
							}
								break;
							default: {
								option_ia_na->Assign(4, ToHex(std_str((*ptr)->ia_na()->data()), false));
							}
								break;
						}
					}
					
					dhcpv6_po->Assign(2, option_ia_na);
					
				}
					break;
					
				case DHCPV6_OPTION_IA_TA: {
					RecordVal* option_ia_ta = new RecordVal(BifType::Record::DHCPV6::DHCPV6_OPTION_IA_TA);					
					option_ia_ta->Assign(0, new Val((*ptr)->ia_ta()->iaid(), TYPE_COUNT));
					option_ia_ta->Assign(1, ToHex(std_str((*ptr)->ia_ta()->data()), false));
					
					dhcpv6_po->Assign(3, option_ia_ta);
				}
					break;
			
				case DHCPV6_OPTION_IAADDR: {
					RecordVal* option_iaaddr = new RecordVal(BifType::Record::DHCPV6::DHCPV6_OPTION_IAADDR);					
					option_iaaddr->Assign(0, new AddrVal(IPAddr(IPv6, (const uint32_t *)((*ptr)->iaaddr()->ipv6_addr()), IPAddr::Network)));
					option_iaaddr->Assign(1, new Val((*ptr)->iaaddr()->preferred_lifetime(), TYPE_COUNT));
					option_iaaddr->Assign(2, new Val((*ptr)->iaaddr()->valid_lifetime(), TYPE_COUNT));
					
					if ( ((*ptr)->iaaddr()->len() - 24) > 0 ) {
						option_iaaddr->Assign(3, ToHex(std_str((*ptr)->iaaddr()->data()), false));
					}
					
					dhcpv6_po->Assign(4, option_iaaddr);
				}
					break;
					
				case DHCPV6_OPTION_ORO: {
					RecordVal* option_oro = new RecordVal(BifType::Record::DHCPV6::DHCPV6_OPTION_ORO);
						
 					VectorVal *t = create_vector_of_count();
					vector<uint16>::const_iterator optptr;
 					unsigned int index = 0;

					for( optptr = (*ptr)->oro()->options()->begin(); optptr != (*ptr)->oro()->options()->end(); ++optptr) {
 					      Val* r = new Val((*optptr), TYPE_COUNT);
 					      t->Assign(index, r);
 					      index++;					  
					}
 					
 					option_oro->Assign(0, t);
 					dhcpv6_po->Assign(5, option_oro);
				}
					break;
				
				case DHCPV6_OPTION_ELAPSED_TIME: {
					RecordVal* option_elapsed_time = new RecordVal(BifType::Record::DHCPV6::DHCPV6_OPTION_ELAPSED_TIME);
					option_elapsed_time->Assign(0, new Val((*ptr)->elapsed_time()->len(), TYPE_COUNT));
					option_elapsed_time->Assign(1, new Val((*ptr)->elapsed_time()->elapsed_time(), TYPE_COUNT));
					dhcpv6_po->Assign(6, option_elapsed_time);
				}
					break;
					
				case DHCPV6_OPTION_VENDOR_CLASS: {
					RecordVal* option_vendor_class = new RecordVal(BifType::Record::DHCPV6::DHCPV6_OPTION_VENDOR_CLASS);
					option_vendor_class->Assign(0, new Val((*ptr)->vendor_class()->enterprise_number(), TYPE_COUNT));
					option_vendor_class->Assign(1, new StringVal(std_str((*ptr)->vendor_class()->vendor_class_data()).c_str()));
					
					dhcpv6_po->Assign(7, option_vendor_class);
				}
					break;
					
				case DHCPV6_OPTION_NAME_SERVERS: { 
					RecordVal* option_name_servers = new RecordVal(BifType::Record::DHCPV6::DHCPV6_OPTION_DNS_SERVERS);
					
					VectorVal *t = create_vector_of_addr();
 					vector<uint128 *>::const_iterator optptr;
  					unsigned int index = 0;

					for( optptr  = (*ptr)->name_servers()->dns_name_servers()->begin(); 
					     optptr != (*ptr)->name_servers()->dns_name_servers()->end(); 
					     ++optptr) {
 					     
 					      uint32 addr[4];
						  addr[0] = htonl((*optptr)->a1());
						  addr[1] = htonl((*optptr)->a2());
						  addr[2] = htonl((*optptr)->a3());
						  addr[3] = htonl((*optptr)->a4());
						  	
  					      Val* r = new AddrVal(IPAddr(IPv6, (const uint32_t *)addr, IPAddr::Network));
  					      t->Assign(index, r);
  					      index++;					  
					}
  					
  					option_name_servers->Assign(0, t);
 					
 					dhcpv6_po->Assign(8, option_name_servers);
				}
					break;
					
				case DHCPV6_OPTION_DOMAIN_LIST: { 
 					RecordVal* option_domain_list = new RecordVal(BifType::Record::DHCPV6::DHCPV6_OPTION_DOMAIN_LIST);
					
					std::string searchlist = "";
					vector<binpac::DHCPV6::dhcpv6_packet_option_domain_list_searchlist *>::const_iterator optptr;
 					
					for( optptr  = (*ptr)->domain_list()->searchlist()->begin(); 
					     optptr != (*ptr)->domain_list()->searchlist()->end(); 
					     ++optptr) {
					     
					     std::string t = std_str((*optptr)->entry());
					     
					     if ( t.length() > 0 ) {
					     	searchlist += t + ".";
					     }
					}
					
					option_domain_list->Assign(0, new StringVal(searchlist));
					
 					dhcpv6_po->Assign(9, option_domain_list);
				}
					break;
					
				case DHCPV6_OPTION_IA_PD: {
					RecordVal* option_ia_pd = new RecordVal(BifType::Record::DHCPV6::DHCPV6_OPTION_IA_PD);
					option_ia_pd->Assign(0, new Val((*ptr)->ia_pd()->iaid(), TYPE_COUNT));
					option_ia_pd->Assign(1, new Val((*ptr)->ia_pd()->t1(), TYPE_COUNT));
					option_ia_pd->Assign(2, new Val((*ptr)->ia_pd()->t2(), TYPE_COUNT));
					
					if ( (*ptr)->ia_pd()->has_option() ) {
						switch((*ptr)->ia_pd()->option()->msgtype()) {
							case DHCPV6_OPTION_IAPREFIX: { 
								RecordVal* option_iaaddr = new RecordVal(BifType::Record::DHCPV6::DHCPV6_OPTION_IAADDR);
								
								uint32 tmp_addr[4];
								tmp_addr[0] = htonl((*ptr)->ia_pd()->option()->iaprefix()->ipv6_prefix()->a1());
								tmp_addr[1] = htonl((*ptr)->ia_pd()->option()->iaprefix()->ipv6_prefix()->a2());
								tmp_addr[2] = htonl((*ptr)->ia_pd()->option()->iaprefix()->ipv6_prefix()->a3());
								tmp_addr[3] = htonl((*ptr)->ia_pd()->option()->iaprefix()->ipv6_prefix()->a4());
							
								option_iaaddr->Assign(0, new AddrVal(IPAddr(IPv6, (const uint32_t *)tmp_addr, IPAddr::Network)));
								option_iaaddr->Assign(1, new Val((*ptr)->ia_pd()->option()->iaprefix()->preferred_lifetime(), TYPE_COUNT));
								option_iaaddr->Assign(2, new Val((*ptr)->ia_pd()->option()->iaprefix()->valid_lifetime(), TYPE_COUNT));
										
								option_ia_pd->Assign(3, option_iaaddr);
							}
								break;
							default: {
								option_ia_pd->Assign(4, ToHex(std_str((*ptr)->ia_pd()->data()), false));
							}
								break;
						}
					}
					
					dhcpv6_po->Assign(10, option_ia_pd);
				}
					break;
					
				case DHCPV6_OPTION_INFORMATION_REFRESH_TIME: {
					RecordVal* option_info_refresh_time = new RecordVal(BifType::Record::DHCPV6::DHCPV6_OPTION_INFO_REFRESH_TIME);
					option_info_refresh_time->Assign(0, new Val((*ptr)->inforefreshtime()->refresh_time(), TYPE_COUNT));
					
					dhcpv6_po->Assign(11, option_info_refresh_time);
				}
					break;
					
				case DHCPV6_OPTION_CLIENT_FQDN: {

					std::cout << "DHCPV6_OPTION_CLIENT_FQDN->dn_len = " << (*ptr)->client_fqdn()->len() << std::endl;

					// RecordVal* option_client_fqdn = new RecordVal(BifType::Record::DHCPV6::DHCPV6_OPTION_CLIENT_FQDN);
					// option_client_fqdn->Assign(0, new Val((*ptr)->client_fqdn()->flags(), TYPE_COUNT));
					// option_client_fqdn->Assign(1, new StringVal(std_str((*ptr)->client_fqdn()->name()).c_str()));

					
					
					// dhcpv6_po->Assign(12, option_client_fqdn);
				}
					break;
					
				default: {
					
					 connection()->bro_analyzer()->ProtocolViolation(fmt("Unsupported or unknown DHCPV6 option code: %d", (*ptr)->option_code()));
				}
					break;
			}
		}
		return dhcpv6_po;
	%}
	
	function proc_dhcpv6_info_req(tid: uint32, options: DHCPV6_packet_option[]): bool
	%{	
		RecordVal* ret = proc_dhcpv6_options(options);
		BifEvent::generate_dhcpv6_info_req(connection()->bro_analyzer(), connection()->bro_analyzer()->Conn(), is_orig(), tid, ret);
		return true;
	%}
	
	function proc_dhcpv6_release(tid: uint32, options: DHCPV6_packet_option[]): bool
	%{	
		RecordVal* ret = proc_dhcpv6_options(options);
		BifEvent::generate_dhcpv6_release(connection()->bro_analyzer(), connection()->bro_analyzer()->Conn(), is_orig(), tid, ret);
		return true;
	%}
	
	function proc_dhcpv6_renew(tid: uint32, options: DHCPV6_packet_option[]): bool
	%{	
		RecordVal* ret = proc_dhcpv6_options(options);
		BifEvent::generate_dhcpv6_renew(connection()->bro_analyzer(), connection()->bro_analyzer()->Conn(), is_orig(), tid, ret);
		return true;
	%}
	
	function proc_dhcpv6_reply(tid: uint32, options: DHCPV6_packet_option[]): bool
	%{	
		RecordVal* ret = proc_dhcpv6_options(options);
		BifEvent::generate_dhcpv6_reply(connection()->bro_analyzer(), connection()->bro_analyzer()->Conn(), is_orig(), tid, ret);
		return true;
	%}
	
	function proc_dhcpv6_request(tid: uint32, options: DHCPV6_packet_option[]): bool
	%{	
		RecordVal* ret = proc_dhcpv6_options(options);
		BifEvent::generate_dhcpv6_request(connection()->bro_analyzer(), connection()->bro_analyzer()->Conn(), is_orig(), tid, ret);
		return true;
	%}
	
	function proc_dhcpv6_advertise(tid: uint32, options: DHCPV6_packet_option[]): bool
	%{	
		RecordVal* ret = proc_dhcpv6_options(options);	
		BifEvent::generate_dhcpv6_advertise(connection()->bro_analyzer(), connection()->bro_analyzer()->Conn(), is_orig(), tid, ret);
		return true;
	%}
	
	function proc_dhcpv6_solict(tid: uint32, options: DHCPV6_packet_option[]): bool
	%{	
		RecordVal* ret = proc_dhcpv6_options(options);
		BifEvent::generate_dhcpv6_solicit(connection()->bro_analyzer(), connection()->bro_analyzer()->Conn(), is_orig(), tid, ret);	
		return true;
	%}

	function proc_dhcpv6_message(msg: DHCPV6_Message): bool
	%{
		try {
			switch ( ${msg.msg_type} ) {
				case DHCPV6_SOLICIT: {
					proc_dhcpv6_solict(${msg.dhcpv6_solicit_msg.transaction_id}, ${msg.dhcpv6_solicit_msg.options});
				}
					break;
				case DHCPV6_ADVERTISE: {
					proc_dhcpv6_advertise(${msg.dhcpv6_advertise_msg.transaction_id}, ${msg.dhcpv6_advertise_msg.options});
				}
					break;
				case DHCPV6_REQUEST: {
					proc_dhcpv6_request(${msg.dhcpv6_request_msg.transaction_id}, ${msg.dhcpv6_request_msg.options});
				}
					break;
				case DHCPV6_REPLY: {
					proc_dhcpv6_reply(${msg.dhcpv6_reply_msg.transaction_id}, ${msg.dhcpv6_reply_msg.options});
				}
					break;
				case DHCPV6_RENEW: {
					proc_dhcpv6_renew(${msg.dhcpv6_renew_msg.transaction_id}, ${msg.dhcpv6_renew_msg.options});
				}
					break;
				case DHCPV6_RELEASE: {
					proc_dhcpv6_release(${msg.dhcpv6_release_msg.transaction_id}, ${msg.dhcpv6_release_msg.options});
				}
					break;
				case DHCPV6_INFORMATION_REQUEST: {
					proc_dhcpv6_info_req(${msg.dhcpv6_info_req_msg.transaction_id}, ${msg.dhcpv6_info_req_msg.options});
				}
					break;
				default: {
					// TO DO: 
					// - Added other IPV6 DHCPv6 message types
					// For now, let's just fall through. 
				}
					break;
			}
		
			connection()->bro_analyzer()->ProtocolConfirmation();
		} catch(...) {
			connection()->bro_analyzer()->ProtocolViolation("DHCPV6 analyzer caught an exception");
		}
		
		return true;
	%}
};

refine typeattr DHCPV6_Message += &let {
	proc_dhcpv6_message = $context.flow.proc_dhcpv6_message(this);
};
