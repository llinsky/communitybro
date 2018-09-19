/*
Licensed to the Apache Software Foundation (ASF) under one
or more contributor license agreements.  See the NOTICE file
distributed with this work for additional information
regarding copyright ownership.  The ASF licenses this file
to you under the Apache License, Version 2.0 (the
"License"); you may not use this file except in compliance
with the License.  You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
KIND, either express or implied.  See the License for the
specific language governing permissions and limitations
under the License.
*/

#ifndef ANALYZER_PROTOCOL_DHCPV6_DHCP_H
#define ANALYZER_PROTOCOL_DHCPV6_DHCP_H

#include "analyzer/protocol/udp/UDP.h"

#include "dhcpv6_analyzer_pac.h"

namespace analyzer {
	namespace dhcpv6_analyzer {
		class DHCPV6_ANALYZER_Analyzer : public analyzer::Analyzer {
			public:
				DHCPV6_ANALYZER_Analyzer(Connection* conn);
				virtual ~DHCPV6_ANALYZER_Analyzer();

				virtual void Done();
				virtual void DeliverPacket(int len, const u_char* data, bool orig, uint64 seq, const IP_Hdr* ip, int caplen);

				static analyzer::Analyzer* InstantiateAnalyzer(Connection* conn) {
					return new DHCPV6_ANALYZER_Analyzer(conn);
				}

			protected:
				binpac::DHCPV6::DHCPV6_Conn* interp;
		};
	}
} // namespace analyzer::*

#endif
