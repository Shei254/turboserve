add_executable(send-money-json-api
	main.c
	../techempower/json.c
)

target_link_libraries(send-money-json-api
	${turboserve_COMMON_LIBS}
	${ADDITIONAL_LIBRARIES}
)
