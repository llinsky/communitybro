
#include "OPENVPN_UDP.h"
#include "Reporter.h"
#include "events.bif.h"

using namespace analyzer::openvpn_udp;

OPENVPN_UDP_Analyzer::OPENVPN_UDP_Analyzer(Connection* c)

: analyzer::Analyzer("OPENVPN_UDP", c)
{
	state = STATE_INIT;
	tls_established = false;
	tls_mode = false;
	packet_count = 0;
	orig_is_client = true;
}

OPENVPN_UDP_Analyzer::~OPENVPN_UDP_Analyzer()
{
	//delete interp;
}

void OPENVPN_UDP_Analyzer::Done()
{
	Analyzer::Done();
}

void OPENVPN_UDP_Analyzer::DeliverPacket(int len, const u_char* data,
	 			  bool orig, uint64 seq, const IP_Hdr* ip, int caplen)
{
	int op;
	int key_id;
	uint8_t c;
	val_list* vl;
	
	if (likely( data && len > 0))
	{
		uint8_t c = *data;
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
				if (len > 41 && ((uint32_t(*(data+33)) <= 1) || (uint32_t(*(data+37)) <= 1)))
				{
					tls_mode = true;
					ProtocolConfirmation();
					orig_is_client = true;
					break;
				}
			case P_CONTROL_HARD_RESET_SERVER_V1:
			case P_CONTROL_HARD_RESET_SERVER_V2:
				if (len > 41 && ((uint32_t(*(data+33)) <= 1) || (uint32_t(*(data+37)) <= 1)))
				{
					tls_mode = true;
					ProtocolConfirmation();
					orig_is_client = false;
					break;
				}
			default:
				//Not TLS, check for shared key mode
				if (len > 40 && ((uint32_t(*(data+32)) <= 1) || (uint32_t(*(data+36)) <= 1)))
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

