add_executable(hello
	main.c
)

target_link_libraries(hello
	${turboserve_COMMON_LIBS}
	${ADDITIONAL_LIBRARIES}
)
