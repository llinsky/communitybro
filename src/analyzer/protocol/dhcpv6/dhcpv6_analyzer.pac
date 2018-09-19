%include binpac.pac
%include bro.pac

%extern{
#include "events.bif.h"
#include "types.bif.h"

#include <iostream>
#include <iomanip>
#include <sstream>
%}

%header{
VectorVal* create_vector_of_count();
VectorVal* create_vector_of_addr();
StringVal* EthAddrToStr(const u_char* addr);
%}
	
%code{
VectorVal* create_vector_of_count() {
    VectorType* vt = new VectorType(base_type(TYPE_COUNT));
    VectorVal* vv = new VectorVal(vt);
    Unref(vt);
    return vv;
}

VectorVal* create_vector_of_addr() {
    VectorType* vt = new VectorType(base_type(TYPE_ADDR));
    VectorVal* vv = new VectorVal(vt);
    Unref(vt);
    return vv;
}

StringVal* EthAddrToStr(const u_char* addr)
{
	char buf[1024];
	snprintf(buf, sizeof(buf), "%02x:%02x:%02x:%02x:%02x:%02x",
			addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
	return new StringVal(buf);
}

StringVal* Dhcpv6ToHex(const std::string& s, bool upper_case)
{
	std::ostringstream ret;
	
	for (string::size_type i = 0; i < s.length(); ++i) {
		ret << std::hex << std::setfill('0') << std::setw(2) << (upper_case ? std::uppercase : std::nouppercase) << (int)s[i];
	}
	
	return new StringVal(ret.str());
}
%}

analyzer DHCPV6 withcontext {
	connection:	DHCPV6_Conn;
	flow:		DHCPV6_Flow;
};

%include dhcpv6_analyzer-protocol.pac
%include dhcpv6_analyzer-analyzer.pac
