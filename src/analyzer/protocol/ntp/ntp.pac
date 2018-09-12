%include binpac.pac
%include bro.pac

%extern{
  #include "types.bif.h"
	#include "events.bif.h"
%}

analyzer NTP withcontext {
	connection: NTP_Conn;
	flow:       NTP_Flow;
};

# Our connection consists of two flows, one in each direction.
connection NTP_Conn(bro_analyzer: BroAnalyzer) {
	upflow   = NTP_Flow(true);
	downflow = NTP_Flow(false);
};

%include ntp-protocol.pac

# Now we define the flow:
flow NTP_Flow(is_orig: bool) {
	datagram = NTP_PDU(is_orig) withcontext(connection, this);

};

%include ntp-analyzer.pac