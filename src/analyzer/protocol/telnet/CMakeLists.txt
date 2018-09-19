include(BroPlugin)

include_directories(BEFORE ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR})

bro_plugin_begin(CBro TELNET)
	bro_plugin_cc(TELNET.cc Plugin.cc)
	bro_plugin_bif(events.bif)
	bro_plugin_pac(telnet.pac telnet-analyzer.pac telnet-protocol.pac)
bro_plugin_end()
