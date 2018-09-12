%include binpac.pac
%include bro.pac

%extern{
#include "consts.bif.h"
#include "types.bif.h"
#include "events.bif.h"
#include <iostream>
#include <iomanip>
#include <sstream>
%}

%header{
StringVal* ToHex(const std::string& s, bool upper_case);
%}
	
	
%code{
StringVal* ToHex(const std::string& s, bool upper_case)
{
	std::ostringstream ret;
	
	for (string::size_type i = 0; i < s.length(); ++i) {
		ret << std::hex << std::setfill('0') << std::setw(2) << (upper_case ? std::uppercase : std::nouppercase) << (int)s[i];
	}
	
	return new StringVal(ret.str());
}
%}

analyzer DCE_RPC withcontext {
	connection : DCE_RPC_Conn;
	flow       : DCE_RPC_Flow;
};

connection DCE_RPC_Conn(bro_analyzer: BroAnalyzer) {
	upflow   = DCE_RPC_Flow(true);
	downflow = DCE_RPC_Flow(false);
};

%include dce_rpc-protocol.pac

%include endpoint-atsvc.pac
%include endpoint-epmapper.pac
%include dce_rpc-analyzer.pac
%include dce_rpc-auth.pac
