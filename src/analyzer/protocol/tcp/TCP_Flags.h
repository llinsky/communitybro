#ifndef ANALYZER_PROTOCOL_TCP_TCP_FLAGS_H
#define ANALYZER_PROTOCOL_TCP_TCP_FLAGS_H

// The following are not included in all systems' tcp.h.

#ifndef TH_ECE
#define TH_ECE  0x40
#endif

#ifndef TH_CWR
#define TH_CWR  0x80
#endif


namespace analyzer { namespace tcp {

class TCP_Flags {
public:
	TCP_Flags(const struct tcphdr* tp)	{ flags = tp->th_flags; }
	TCP_Flags()	{ flags = 0; }

	bool SYN() const	{ return flags & TH_SYN; }
	bool FIN() const	{ return flags & TH_FIN; }
	bool RST() const	{ return flags & TH_RST; }
	bool ACK() const	{ return flags & TH_ACK; }
	bool URG() const	{ return flags & TH_URG; }
	bool PUSH() const	{ return flags & TH_PUSH; }
	bool CWR() const	{ return flags & TH_CWR; }
	bool ECE() const	{ return flags & TH_ECE; }

	string AsString() const;

	u_char flags;
};

inline string TCP_Flags::AsString() const
	{
	char tcp_flags[10];
	char* p = tcp_flags;

	if ( SYN() )
		*p++ = 'S';

	if ( FIN() )
		*p++ = 'F';

	if ( RST() )
		*p++ = 'R';

	if ( ACK() )
		*p++ = 'A';

	if ( PUSH() )
		*p++ = 'P';

	if ( URG() )
		*p++ = 'U';

	if ( CWR() )
		*p++ = 'C';

	if ( ECE() )
		*p++ = 'E';

	*p++ = '\0';
	return tcp_flags;
	}
}


}

#endif
