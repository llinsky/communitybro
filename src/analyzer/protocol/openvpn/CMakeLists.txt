include(BroPlugin)
include_directories(BEFORE ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR})

project(Bro-Plugin-OPENVPN)

cmake_minimum_required(VERSION 2.8)

if ( NOT BRO_DIST )
    message(FATAL_ERROR "BRO_DIST not set")
endif ()

set(CMAKE_MODULE_PATH ${BRO_DIST}/cmake)

bro_plugin_begin(CBro OPENVPN)
bro_plugin_cc(src/Plugin.cc)
bro_plugin_cc(src/OPENVPN_TCP.cc src/OPENVPN_UDP.cc)
bro_plugin_bif(src/events.bif)
bro_plugin_end()
