include(BroPlugin)
include_directories(BEFORE ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR})

set(CMAKE_MODULE_PATH ${BRO_DIST}/cmake)

bro_plugin_begin(CBro TFTP)
	bro_plugin_cc(TFTP.cc Plugin.cc)
	bro_plugin_bif(events.bif)
	bro_plugin_pac(tftp.pac tftp-analyzer.pac tftp-protocol.pac)
bro_plugin_end()
