#include "OPENVPN_TCP.h"
#include "analyzer/protocol/tcp/TCP_Reassembler.h"
#include "Reporter.h"
#include "events.bif.h"

using namespace analyzer::openvpn_tcp;

OPENVPN_TCP_Analyzer::OPENVPN_TCP_Analyzer(Connection* c): tcp::TCP_ApplicationAnalyzer("OPENVPN_TCP", c)
{
	state = STATE_INIT;
	tls_established = false;
	tls_mode = false;
	packet_count = 0;
	orig_is_client = true;

	had_gap = false;
}

OPENVPN_TCP_Analyzer::~OPENVPN_TCP_Analyzer()
{
	//delete interp;
}

void OPENVPN_TCP_Analyzer::Done()
{
	tcp::TCP_ApplicationAnalyzer::Done();
}

void OPENVPN_TCP_Analyzer::EndpointEOF(bool is_orig)
{
	tcp::TCP_ApplicationAnalyzer::EndpointEOF(is_orig);
	//interp->FlowEOF(is_orig);
}

void OPENVPN_TCP_Analyzer::DeliverStream(int len, const u_char* data, bool orig)
{
	tcp::TCP_ApplicationAnalyzer::DeliverStream(len, data, orig);

	assert(TCP());
	if ( TCP()->IsPartial() )
		return;

	if ( had_gap )
		// If only one side had a content gap, we could still try to
		// deliver data to the other side if the script layer can handle this.
		return;

	int op;
	int key_id;
	uint8_t c;
	val_list* vl;

	if (likely( data && len > 0))
	{
		uint8_t c = *(data+2);
		op = c >> P_OPCODE_SHIFT;
		key_id = c & P_KEY_ID_MASK;
	}
	else
	{
		//Note: protocol violations are really inefficient -- why do these generate an
		//	event and get handled at the script layer?
		ProtocolViolation(fmt("Non-OpenVPN-compliant packet received on port 1194, \
			no payload received."), NULL, 0);
		return;
	}

	if (unlikely(packet_count == 0))
	{
		//Do initial protocol checks
		switch (op)
		{
			//Check for TLS mode
			case P_CONTROL_HARD_RESET_CLIENT_V1:
			case P_CONTROL_HARD_RESET_CLIENT_V2:
				if (len > 43 && ((uint32_t(*(data+35)) <= 1) || (uint32_t(*(data+39)) <= 1)))
				{
					tls_mode = true;
					ProtocolConfirmation();
					orig_is_client = true;
					break;
				}
			case P_CONTROL_HARD_RESET_SERVER_V1:
			case P_CONTROL_HARD_RESET_SERVER_V2:
				if (len > 43 && ((uint32_t(*(data+35)) <= 1) || (uint32_t(*(data+39)) <= 1)))
				{
					tls_mode = true;
					ProtocolConfirmation();
					orig_is_client = false;
					break;
				}
			default:
				//Not TLS, check for shared key mode
				if (len > 42 && ((uint32_t(*(data+34)) <= 1) || (uint32_t(*(data+38)) <= 1)))
				{
					tls_mode = false;
					ProtocolConfirmation();
					break;
				}
				ProtocolViolation("Not the start of an OpenVPN handshake", NULL, 0);
		}
	}

	packet_count++;


	if (tls_mode) {
		switch (op)
		{
			case P_CONTROL_HARD_RESET_CLIENT_V1:
				state = STATE_HARD_RESET_CLIENT;
				tls_established = false;

				vl = new val_list;
				vl->append(BuildConnVal());
				vl->append(new StringVal("HARD RESET CLIENT_V1"));
				ConnectionEvent(openvpn_hard_reset, vl);

				break;
			case P_CONTROL_HARD_RESET_SERVER_V1:
				state = STATE_HARD_RESET_SERVER;
				tls_established = false;

				vl = new val_list;
				vl->append(BuildConnVal());
				vl->append(new StringVal("HARD RESET SERVER_V1"));
				ConnectionEvent(openvpn_hard_reset, vl);

				break;
			case P_CONTROL_SOFT_RESET_V1:
				state = STATE_SOFT_RESET;

				if (unlikely(state == STATE_INIT))
				{
					ProtocolViolation(fmt("Illegal OpenVPN TLS state transition \
						- INIT to SOFT_RESET"), NULL, 0);
					return;
				}

				vl = new val_list;
				vl->append(BuildConnVal());
				if (orig_is_client == orig)
				{
					vl->append(new StringVal("CLIENT"));
				}
				else
				{
					vl->append(new StringVal("SERVER"));
				}
				ConnectionEvent(openvpn_soft_reset, vl);

				break;
			case P_CONTROL_V1:
				if (likely(state != STATE_INIT))
				{
					state = STATE_CONTROL;
				}
				break;
			case P_ACK_V1:
				if (unlikely(state == STATE_INIT))
				{
					ProtocolViolation(fmt("Illegal OpenVPN TLS state transition \
						- INIT to ACK"), NULL, 0);
					return;
				}
				//OpenVPN Acks are sent for control messages, including resets
				break;
			case P_DATA_V1:
			case P_DATA_V2:
				if ((state == STATE_CONTROL))
				{
					tls_established = true; //this is one way to check...

					vl = new val_list;
					vl->append(BuildConnVal());
					ConnectionEvent(openvpn_tlsestablished, vl);

					state = STATE_DATA;
				}
				else if (likely((state == STATE_DATA) && (tls_established)))
				{
					state = STATE_DATA;
				}
				else
				{
					ProtocolViolation(fmt("Illegal OpenVPN TLS state transition \
						- INIT to DATA, op: %d", op), NULL, 0);
					return;
				}
				
				break;

			case P_CONTROL_HARD_RESET_CLIENT_V2:
				state = STATE_HARD_RESET_CLIENT;
				tls_established = false;

				vl = new val_list;
				vl->append(BuildConnVal());
				vl->append(new StringVal("HARD RESET CLIENT_V2"));
				ConnectionEvent(openvpn_hard_reset, vl);

				break;
			case P_CONTROL_HARD_RESET_SERVER_V2:
				state = STATE_HARD_RESET_SERVER;
				tls_established = false;

				vl = new val_list;
				vl->append(BuildConnVal());
				vl->append(new StringVal("HARD RESET SERVER_V2"));
				ConnectionEvent(openvpn_hard_reset, vl);

				break;
			default:
				reporter->Weird(fmt("Unknown OpenVPN TLS Packet received, opcode: %d", op));
				ProtocolViolation(fmt("Unknown OpenVPN TLS Packet received, opcode: %d", op), \
					NULL, 0);
				return;
		}
	}
	else
	{
		//TODO: (we need to actively track the state of the exchange to know when more
		//	specific events occur. For now, just signify that there's an exchange.)
		if (unlikely(packet_count <= 1))
		{
			vl = new val_list;
			vl->append(BuildConnVal());
			vl->append(new StringVal("PRE_SHARED_KEY_INIT"));
			ConnectionEvent(openvpn_hard_reset, vl);
		}
	}
}

void OPENVPN_TCP_Analyzer::Undelivered(uint64 seq, int len, bool orig)
{
	tcp::TCP_ApplicationAnalyzer::Undelivered(seq, len, orig);
	had_gap = true;
}
