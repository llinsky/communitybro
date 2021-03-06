// Generated by binpac_quickstart

#ifndef ANALYZER_PROTOCOL_TELNET_TELNET_H
#define ANALYZER_PROTOCOL_TELNET_TELNET_H

#include "events.bif.h"


#include "analyzer/protocol/tcp/TCP.h"

#include "telnet_pac.h"

namespace analyzer { namespace telnet {

class TELNET_Analyzer

: public tcp::TCP_ApplicationAnalyzer {

public:
	TELNET_Analyzer(Connection* conn);
	virtual ~TELNET_Analyzer();

	// Overriden from Analyzer.
	virtual void Done();
	
	virtual void DeliverStream(int len, const u_char* data, bool orig);
	virtual void Undelivered(uint64 seq, int len, bool orig);

	// Overriden from tcp::TCP_ApplicationAnalyzer.
	virtual void EndpointEOF(bool is_orig);
	

	static analyzer::Analyzer* InstantiateAnalyzer(Connection* conn)
		{ return new TELNET_Analyzer(conn); }

protected:
	binpac::TELNET::TELNET_Conn* interp;
	bool had_gap;
	
};
} } 

#endif
