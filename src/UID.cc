// See the file "COPYING" in the main distribution directory for copyright.

#include <cstdlib>
#include <string>
#include "UID.h"
#include "util.h"
#include <limits.h>		// UINT32_MAX
#include <time.h>		// time()
#include <stdlib.h>		// srandom(), random(), strtol()

#include <string>
#include <map>

extern uint32 g_rolling_conn_counter;

using namespace Bro;
using namespace std;

static std::map<std::string, std::pair<int,int> > g_wp_map;

void UID::Set(bro_uint_t bits, const uint64* v, size_t n)
{
	initialized = true;

	for ( size_t i = 0; i < BRO_UID_LEN; ++i ) {
		uid[i] = 0;
	}

	if ( bits > BRO_UID_LEN * 64 ) {
		bits = BRO_UID_LEN * 64;
	}

	div_t res = div(bits, 64);
	size_t size = res.rem ? res.quot + 1 : res.quot;

	for ( size_t i = 0; i < size; ++i ) {
		uid[i] = v && i < n ? v[i] : calculate_unique_id();
	}

	if ( res.rem ) {
		uid[0] >>= 64 - res.rem;
	}
}


std::pair<uint32, uint32> UID::Determine_Worker_and_Process_IDs(const u_char *peer_description)
{
	std::pair<int,int> ret;
	int worker_id  = 0;
	int process_id = 0;

	std::map<std::string, std::pair<int,int> >::iterator t_wp_iter = g_wp_map.find(std::string((char *)peer_description));

	if(t_wp_iter != g_wp_map.end()) {
		ret = t_wp_iter->second;
	} else {
		std::vector<std::string> tokens = split_tokens(std::string((char *)peer_description), '-');

		switch(tokens.size()) {
			case 3:  {      // worker
				if(tokens[0] == "worker") {
					worker_id  = strtol(tokens[1].c_str(), NULL, 10);
					process_id = strtol(tokens[2].c_str(), NULL, 10);
				}
			}
			break;
			case 2: {       // proxy
				if(tokens[0] == "proxy") {
					process_id = strtol(tokens[1].c_str(), NULL, 10);
				}
			}
			break;
			case 1: {       // manager or bro
				if(tokens[0] == "manager" || tokens[0] == "bro") {
					worker_id  = 0;
					process_id = 0;
				}
			}
			break;
			default: {
				worker_id  = 0xFFF;
				process_id = 0xFFF;
			}
			break;

		}

		ret = std::make_pair(worker_id, process_id);
		g_wp_map[std::string((char *)peer_description)] = ret;
	}

	return ret;
}

//
// https://confluence.packetsled.com/display/AR/Optimal+Packetsled+UID+structure+for+clustered+Bro+sensors
//
void UID::Set_conn_uid(double start_time, const u_char *peer_description)
{
	initialized = true;
	conn_uid = "";

	if(g_rolling_conn_counter >= 0xFFFFFF-1) {
		srandom(time(0));
		g_rolling_conn_counter = (random() & 0x00FFFFFF);
	}  else {
		g_rolling_conn_counter++;
	}

	std::pair<uint32, uint32> t_ids = Determine_Worker_and_Process_IDs(peer_description);

	// 4-byte -
	// value representing the seconds since the Unix epoch = Connection::start_time
	conn_uid  = to_hex<uint32>((uint32)start_time);

	// 3-byte -
	// machine identifier = worker id parsed from peer_description,
	// e.g. "worker-2-13" means that worker id == 2
	conn_uid += to_hex(t_ids.first, "", true, 6);

	// 2-byte -
	// process id = process id parsed from peer_description,
	// e.g. "worker-2-13" means that process id == 13
	conn_uid += to_hex(t_ids.second, "", true, 4);

	// 3-byte -
	// counter, starting with a random value
	conn_uid += to_hex(g_rolling_conn_counter, "", true, 6);
}
