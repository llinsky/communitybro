// Developed by Leo Linsky for Packetsled. Copyright 2016.

#include "TFTP.h"

#include "Reporter.h"

#include "events.bif.h"

using namespace analyzer::TFTP;

TFTP_Analyzer::TFTP_Analyzer(Connection* c)

: analyzer::Analyzer("TFTP", c)
{
	interp = new binpac::TFTP::TFTP_Conn(this);	
}

TFTP_Analyzer::~TFTP_Analyzer()
{
	delete interp;
}

void TFTP_Analyzer::Done()
{
	
	Analyzer::Done();
	
}

void TFTP_Analyzer::DeliverPacket(int len, const u_char* data,
	 			  bool orig, uint64 seq, const IP_Hdr* ip, int caplen)
{
	Analyzer::DeliverPacket(len, data, orig, seq, ip, caplen);

	try
	{
		interp->NewData(orig, data, data + len);
	}
	catch ( const binpac::Exception& e )
	{
		ProtocolViolation(fmt("Binpac exception: %s", e.c_msg()));
	}
}
