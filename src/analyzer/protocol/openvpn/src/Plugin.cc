#include "plugin/Plugin.h"

#include "OPENVPN_UDP.h"
#include "OPENVPN_TCP.h"

namespace plugin {
namespace CBro_OPENVPN {

class Plugin : public plugin::Plugin {
public:
	plugin::Configuration Configure()
		{

		AddComponent(new ::analyzer::Component("OPENVPN_UDP",
		             ::analyzer::openvpn_udp::OPENVPN_UDP_Analyzer::InstantiateAnalyzer));

		AddComponent(new ::analyzer::Component("OPENVPN_TCP",
		             ::analyzer::openvpn_tcp::OPENVPN_TCP_Analyzer::InstantiateAnalyzer));

		plugin::Configuration config;
		config.name = "CBro::OPENVPN";
		config.description = "OpenVPN analyzer";
		return config;
		}
} plugin;

}
}
