include(BroPlugin)
include_directories(BEFORE ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR})

project(Bro-Plugin-DHCPV6_ANALYZER)

cmake_minimum_required(VERSION 2.8)

if ( NOT BRO_DIST )
    message(FATAL_ERROR "BRO_DIST not set")
endif ()

set(CMAKE_MODULE_PATH ${BRO_DIST}/cmake)

bro_plugin_begin(CBro DHCPV6_ANALYZER)
bro_plugin_cc(src/Plugin.cc)
bro_plugin_cc(src/DHCPV6_ANALYZER.cc)
bro_plugin_bif(src/events.bif)
bro_plugin_bif(src/types.bif)
bro_plugin_pac(src/dhcpv6_analyzer.pac 
	       src/dhcpv6_analyzer-analyzer.pac 
	       src/dhcpv6_analyzer-protocol.pac)
bro_plugin_end()
