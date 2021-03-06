
#ifndef ANALYZER_PROTOCOL_OPENVPN_OPENVPN_H
#define ANALYZER_PROTOCOL_OPENVPN_OPENVPN_H

#include "events.bif.h"
#include "analyzer/protocol/tcp/TCP.h"

// Note: OpenVPN can use UDP or TCP on any port, with or without SSL. This analyzer is
// currently limited to UDP/TCP with or without SSL over the default port 1194. 

#define 	P_KEY_ID_MASK   0x07
#define 	P_OPCODE_SHIFT   3

#define 	P_CONTROL_HARD_RESET_CLIENT_V1   1 /* initial key from client, forget previous state */
#define 	P_CONTROL_HARD_RESET_SERVER_V1   2 /* initial key from server, forget previous state */
#define 	P_CONTROL_SOFT_RESET_V1   3 /* new key, graceful transition from old to new key */
#define 	P_CONTROL_V1   4 /* control channel packet (usually TLS ciphertext) */
#define 	P_ACK_V1   5 /* acknowledgement for packets received */
#define 	P_DATA_V1   6 /* data channel packet */
#define 	P_DATA_V2   9 /* data channel packet with peer-id */
#define 	P_CONTROL_HARD_RESET_CLIENT_V2   7 /* initial key from client, forget previous state */
#define 	P_CONTROL_HARD_RESET_SERVER_V2   8 /* initial key from server, forget previous state */


namespace analyzer { namespace openvpn_tcp {

//Shallow state tracking, clearly illegal state transitions result in protocol violation
typedef enum {
	STATE_INIT,

	STATE_HARD_RESET_CLIENT,
	STATE_HARD_RESET_SERVER,
	STATE_SOFT_RESET,
	STATE_CONTROL, //only Control messages have ACKs
	STATE_DATA,

	STATE_DONE,

} OPENVPN_STATE;


// OpenVPN has many flavors and options that affect protocol headers (see README) so we don't 
//	try parsing every single field for now. Fields that vary include packet_id (4 or 8 bytes), 
//	hmac (16 or 20 bytes), opcode_key, etc. which means 8+ different binpac parsing streams 
//	which is unnecessary for the info of interest

/*
struct openvpn_tls_control
{
	uint16_t	packet_len;
	uint8_t 	opcode_key;
	uint8_t 	session_id[8];
	uint8_t 	hmac[20];
	uint32_t 	packet_id
};

struct openvpn_tls_data
{
	uint16_t	packet_len;
	uint8_t 	opcode_key;
	uint8_t 	session_id[8];
	uint8_t 	hmac[20];
};
*/

class OPENVPN_TCP_Analyzer: public tcp::TCP_ApplicationAnalyzer {

public:
	OPENVPN_TCP_Analyzer(Connection* conn);
	virtual ~OPENVPN_TCP_Analyzer();

	// Overriden from Analyzer.
	virtual void Done();
	
	virtual void DeliverStream(int len, const u_char* data, bool orig);
	virtual void Undelivered(uint64 seq, int len, bool orig);

	// Overriden from tcp::TCP_ApplicationAnalyzer.
	virtual void EndpointEOF(bool is_orig);
	

	static analyzer::Analyzer* InstantiateAnalyzer(Connection* conn)
		{ return new OPENVPN_TCP_Analyzer(conn); }

protected:

	//void StartTLS();

	//binpac::OPENVPN::OPENVPN_Conn* interp;
	
	bool had_gap;
	int state;
	bool tls_established;
	bool tls_mode;
	int packet_count;
	bool orig_is_client;
};

} } // namespace analyzer::* 

#endif
