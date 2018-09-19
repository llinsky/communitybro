include(BroPlugin)
include_directories(BEFORE ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR})

set(CMAKE_MODULE_PATH ${BRO_DIST}/cmake)

bro_plugin_begin(CBro DHCPV6_ANALYZER)
bro_plugin_cc(Plugin.cc)
bro_plugin_cc(DHCPV6_ANALYZER.cc)
bro_plugin_bif(events.bif)
bro_plugin_bif(types.bif)
bro_plugin_pac(dhcpv6_analyzer.pac 
	       dhcpv6_analyzer-analyzer.pac 
	       dhcpv6_analyzer-protocol.pac)
bro_plugin_end()
