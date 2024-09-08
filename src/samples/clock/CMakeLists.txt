add_executable(clock
	main.c
	gifenc.c
	xdaliclock.c
	numbers.c
	blocks.c
	pong.c
)

target_link_libraries(clock
	${turboserve_COMMON_LIBS}
	${ADDITIONAL_LIBRARIES}
	m
)
