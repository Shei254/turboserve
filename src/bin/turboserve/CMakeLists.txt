include_directories(BEFORE ${CMAKE_BINARY_DIR})

add_executable(turboserve main.c)

target_link_libraries(turboserve
	${turboserve_COMMON_LIBS}
	${ADDITIONAL_LIBRARIES}
)

INSTALL(TARGETS turboserve DESTINATION ${CMAKE_INSTALL_FULL_BINDIR})
