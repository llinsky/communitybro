// Developed by Leo Linsky for Packetsled. Copyright 2016.

#ifndef ANALYZER_PROTOCOL_TFTP_TFTP_H
#define ANALYZER_PROTOCOL_TFTP_TFTP_H

#include "events.bif.h"


#include "analyzer/protocol/udp/UDP.h"

#include "tftp_pac.h"

namespace analyzer { namespace TFTP {

class TFTP_Analyzer

: public analyzer::Analyzer {

public:
	TFTP_Analyzer(Connection* conn);
	virtual ~TFTP_Analyzer();

	// Overriden from Analyzer.
	virtual void Done();
	
	virtual void DeliverPacket(int len, const u_char* data, bool orig,
					uint64 seq, const IP_Hdr* ip, int caplen);
	

	static analyzer::Analyzer* InstantiateAnalyzer(Connection* conn)
		{ return new TFTP_Analyzer(conn); }

protected:
	binpac::TFTP::TFTP_Conn* interp;
	
};

} } // namespace analyzer::* 

#endif