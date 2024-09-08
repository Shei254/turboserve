add_executable(chatr
	main.c
	../techempower/json.c
)

target_link_libraries(chatr
	${turboserve_COMMON_LIBS}
	${ADDITIONAL_LIBRARIES}
)
