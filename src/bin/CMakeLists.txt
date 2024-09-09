add_subdirectory(tools)

if (NOT ${CMAKE_BUILD_TYPE} MATCHES "Coverage")
	add_subdirectory(turboserve)
endif()

add_subdirectory(testrunner)
