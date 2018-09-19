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

#include "plugin/Plugin.h"

#include "DHCPV6_ANALYZER.h"

namespace plugin {
namespace CBro_DHCPV6_ANALYZER {

class Plugin : public plugin::Plugin {
public:
	plugin::Configuration Configure()
		{
		AddComponent(new ::analyzer::Component("DHCPV6",
		             ::analyzer::dhcpv6_analyzer::DHCPV6_ANALYZER_Analyzer::InstantiateAnalyzer));

		plugin::Configuration config;
		config.name = "CBro::DHCPV6_ANALYZER";
		config.description = "DHCPV6 Analyzer";
		return config;
		}
} plugin;

}
}
