# Developed by Leo Linsky for Packetsled. Copyright 2016.

# Analyzer for Trivial File Transfer Protocol
#  - tftp-protocol.pac: describes the TFTP protocol messages
#  - tftp-analyzer.pac: describes the TFTP analyzer code

%include binpac.pac
%include bro.pac

%extern{
	#include "events.bif.h"
%}

analyzer TFTP withcontext {
	connection: TFTP_Conn;
	flow:       TFTP_Flow;
};

# Our connection consists of two flows, one in each direction.
connection TFTP_Conn(bro_analyzer: BroAnalyzer) {
	upflow   = TFTP_Flow(true);
	downflow = TFTP_Flow(false);
};

%include tftp-protocol.pac

# Now we define the flow:
flow TFTP_Flow(is_orig: bool) {

	# ## TODO: Determine if you want flowunit or datagram parsing:

	# Using flowunit will cause the analyzer to buffer incremental input.
	# This is needed for &oneline and &length. If you don't need this, you'll
	# get better performance with datagram.

	# flowunit = TFTP_PDU(is_orig) withcontext(connection, this);
	datagram = TFTP_PDU(is_orig) withcontext(connection, this);

};

%include tftp-analyzer.pac