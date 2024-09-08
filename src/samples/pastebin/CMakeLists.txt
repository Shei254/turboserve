add_executable(pastebin
	main.c
)

target_link_libraries(pastebin
	${turboserve_COMMON_LIBS}
	${ADDITIONAL_LIBRARIES}
)
