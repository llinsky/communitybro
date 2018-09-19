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

#include "DHCPV6_ANALYZER.h"

#include "events.bif.h"

using namespace analyzer::dhcpv6_analyzer;

DHCPV6_ANALYZER_Analyzer::DHCPV6_ANALYZER_Analyzer(Connection* conn) : Analyzer("DHCPV6", conn)
{
	interp = new binpac::DHCPV6::DHCPV6_Conn(this);
}

DHCPV6_ANALYZER_Analyzer::~DHCPV6_ANALYZER_Analyzer()
{
	delete interp;
}

void DHCPV6_ANALYZER_Analyzer::Done()
{
	Analyzer::Done();
}

void DHCPV6_ANALYZER_Analyzer::DeliverPacket(int len, const u_char* data,
			bool orig, uint64 seq, const IP_Hdr* ip, int caplen)
{
	Analyzer::DeliverPacket(len, data, orig, seq, ip, caplen);
	interp->NewData(orig, data, data + len);
}
