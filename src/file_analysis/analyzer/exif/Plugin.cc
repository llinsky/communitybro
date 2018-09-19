#include "plugin/Plugin.h"

#include "EXIF.h"

namespace file_analysis { class EXIF; }

namespace plugin {
	namespace CBro_EXIF {
		class Plugin : public plugin::Plugin
		{
			public:
				plugin::Configuration Configure()
				{
					AddComponent(new ::file_analysis::Component("EXIF", ::file_analysis::EXIF::Instantiate));

					plugin::Configuration config;
					config.name = "CBro::EXIF";
					config.description = "Exchangeable Image File Format Analyzer";
					config.version.major = 1;
					config.version.minor = 0;
					
					return config;
				}
		} plugin;
	}
}
