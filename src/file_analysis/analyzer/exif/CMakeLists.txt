include(BroPlugin)
include_directories(BEFORE ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR})

set(CMAKE_MODULE_PATH ${BRO_DIST}/cmake)

bro_plugin_begin(CBro EXIF)
bro_plugin_cc(easy_exif.cpp EXIF.cc Plugin.cc ../../Analyzer.cc)
bro_plugin_bif(types.bif)
bro_plugin_bif(events.bif)
bro_plugin_end()
