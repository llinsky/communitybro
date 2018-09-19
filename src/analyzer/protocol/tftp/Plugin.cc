
#include "plugin/Plugin.h"

#include "TFTP.h"

namespace plugin {
namespace CBro_TFTP {

class Plugin : public plugin::Plugin {
public:
	plugin::Configuration Configure()
		{
		AddComponent(new ::analyzer::Component("TFTP",
		             ::analyzer::TFTP::TFTP_Analyzer::InstantiateAnalyzer));

		plugin::Configuration config;
		config.name = "CBro::TFTP";
		config.description = "Trivial File Transfer Protocol Analyzer";
		return config;
		}
} plugin;

}
}
