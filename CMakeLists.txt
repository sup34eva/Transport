cmake_minimum_required (VERSION 2.6)
include(ExternalProject)

project (Transport)

include_directories(include)

IF (WIN32)
    ExternalProject_Add(
        winpcap
        URL http://www.winpcap.org/install/bin/WpdPack_4_1_2.zip
        PREFIX ${CMAKE_CURRENT_LIST_DIR}/dependencies
        CONFIGURE_COMMAND ""
        BUILD_COMMAND ""
        INSTALL_COMMAND ""
        LOG_DOWNLOAD ON
    )

    include_directories(${CMAKE_CURRENT_LIST_DIR}/dependencies/src/winpcap/Include)
    link_directories(${CMAKE_CURRENT_LIST_DIR}/dependencies/src/winpcap/Lib)

    add_definitions(-D_ALLOW_KEYWORD_MACROS -DHAVE_REMOTE)
ENDIF()

set(SOURCES
	include/Client.hpp src/Client.cpp
	include/EventEmitter.hpp
	include/Events.hpp src/Events.cpp
	include/Packet.hpp src/Packet.cpp
	include/Request.hpp src/Request.cpp
	include/Response.hpp src/Response.cpp
	include/Server.hpp src/Server.cpp
	include/Transport.hpp src/Transport.cpp
)

add_library(Transport STATIC ${SOURCES})
add_executable(NetTest test/NetTest.cpp)

add_dependencies(NetTest Transport)
target_link_libraries(NetTest Transport)

IF (WIN32)
    add_dependencies(Transport winpcap)
    target_link_libraries(Transport wpcap Ws2_32)
ENDIF()
