if (CMAKE_CROSSCOMPILING)
	set(IMPORT_EXECUTABLES "IMPORTFILE-NOTFILE" CACHE FILEPATH "Point it to the export file from a native build")
	include(${IMPORT_EXECUTABLES})
endif ()

set(SOURCES
        turboserve-arena.c
	turboserve-array.c
	turboserve.c
	turboserve-cache.c
	turboserve-config.c
	turboserve-coro.c
	turboserve-h2-huffman.c
	turboserve-http-authorize.c
	turboserve-io-wrappers.c
	turboserve-job.c
	turboserve-pubsub.c
	turboserve-readahead.c
	turboserve-request.c
	turboserve-response.c
	turboserve-socket.c
	turboserve-status.c
	turboserve-straitjacket.c
	turboserve-strbuf.c
	turboserve-tables.c
	turboserve-template.c
	turboserve-thread.c
	turboserve-time.c
	turboserve-tq.c
	turboserve-trie.c
	turboserve-websocket.c

	turboserve-mod-fastcgi.c
	turboserve-mod-redirect.c
	turboserve-mod-response.c
	turboserve-mod-rewrite.c
	turboserve-mod-serve-files.c

	missing.c
	missing-epoll.c
	missing-pthread.c

	base64.c
	hash.c
	int-to-str.c
	list.c
	patterns.c
	realpathat.c
	sd-daemon.c
	sha1.c
	timeout.c
)

if (turboserve_HAVE_LUA)
	list(APPEND SOURCES turboserve-lua.c turboserve-mod-lua.c)
endif ()

add_library(turboserve-static STATIC ${SOURCES})
set_target_properties(turboserve-static PROPERTIES
   OUTPUT_NAME turboserve CLEAN_DIRECT_OUTPUT 1)
set_target_properties(turboserve-static PROPERTIES COMPILE_FLAGS "-fPIC")

# Can't call add_library() without source files. Create an empty .c file,
# then link with the static library just recently built.
file(WRITE "${CMAKE_BINARY_DIR}/empty.c" "")
add_library(turboserve-shared SHARED "${CMAKE_BINARY_DIR}/empty.c")
target_link_libraries(turboserve-shared
	${turboserve_COMMON_LIBS}
	${ADDITIONAL_LIBRARIES}
)
if (NOT APPLE)
	target_link_libraries(turboserve-shared
		-Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/libturboserve.sym
	)
endif ()

set_target_properties(turboserve-shared PROPERTIES
   OUTPUT_NAME turboserve CLEAN_DIRECT_OUTPUT 1)


# Build mimegen
add_custom_command(
        OUTPUT ${CMAKE_BINARY_DIR}/mime-types.h
        COMMAND mimegen
                ${CMAKE_SOURCE_DIR}/src/bin/tools/mime.types >
                ${CMAKE_BINARY_DIR}/mime-types.h
        DEPENDS ${CMAKE_SOURCE_DIR}/src/bin/tools/mime.types mimegen
	COMMENT "Building MIME type table"
)
add_custom_target(generate_mime_types_table
        DEPENDS ${CMAKE_BINARY_DIR}/mime-types.h
)
add_dependencies(turboserve-static generate_mime_types_table)


add_custom_command(
        OUTPUT ${CMAKE_BINARY_DIR}/lookup-http-status.h
        COMMAND statuslookupgen > ${CMAKE_BINARY_DIR}/lookup-http-status.h
        DEPENDS statuslookupgen
	COMMENT "Building HTTP status lookup perfect hash table"
)
add_custom_target(generate_lookup_http_status
        DEPENDS ${CMAKE_BINARY_DIR}/lookup-http-status.h
)
add_dependencies(turboserve-static generate_lookup_http_status)


add_custom_command(
        OUTPUT ${CMAKE_BINARY_DIR}/servefile-data.h
        COMMAND bin2hex
                ${CMAKE_SOURCE_DIR}/wwwroot/icons/back.gif back_gif
                ${CMAKE_SOURCE_DIR}/wwwroot/icons/file.gif file_gif
                ${CMAKE_SOURCE_DIR}/wwwroot/icons/folder.gif folder_gif
                ${CMAKE_SOURCE_DIR}/src/lib/servefile-template.html servefile_template
		>
                ${CMAKE_BINARY_DIR}/servefile-data.h
        DEPENDS ${CMAKE_SOURCE_DIR}/wwwroot/icons/back.gif
                ${CMAKE_SOURCE_DIR}/wwwroot/icons/file.gif
                ${CMAKE_SOURCE_DIR}/wwwroot/icons/folder.gif
                ${CMAKE_SOURCE_DIR}/src/lib/servefile-template.html
                bin2hex
	COMMENT "Bundling data for serve-files module"
)
add_custom_target(bundle_servefile_data
        DEPENDS ${CMAKE_BINARY_DIR}/servefile-data.h
)
add_dependencies(turboserve-static bundle_servefile_data)

add_custom_command(
        OUTPUT ${CMAKE_BINARY_DIR}/response-data.h
        COMMAND bin2hex
                ${CMAKE_SOURCE_DIR}/src/lib/response-template.html response_template
		>
                ${CMAKE_BINARY_DIR}/response-data.h
        DEPENDS ${CMAKE_SOURCE_DIR}/src/lib/response-template.html
                bin2hex
	COMMENT "Bundling data for response"
)
add_custom_target(bundle_response_data
        DEPENDS ${CMAKE_BINARY_DIR}/response-data.h
)
add_dependencies(turboserve-static bundle_response_data)

if (NOT HAVE_BUILTIN_FPCLASSIFY)
	set(ADDITIONAL_LIBRARIES ${ADDITIONAL_LIBRARIES} -lm PARENT_SCOPE)
endif ()

if (turboserve_HAVE_LIBUCONTEXT)
	message(STATUS "Using libucontext/${CMAKE_SYSTEM_PROCESSOR} for coroutine context switching")

	include(ExternalProject)

	ExternalProject_Add(libucontext
		SOURCE_DIR ${CMAKE_SOURCE_DIR}/src/3rdparty/libucontext

		BUILD_IN_SOURCE ON

		CONFIGURE_COMMAND ""
		BUILD_COMMAND make libucontext.a FREESTANDING=yes
		INSTALL_COMMAND make install-static install-headers DESTDIR=${CMAKE_BINARY_DIR} FREESTANDING=yes

		BUILD_BYPRODUCTS ${CMAKE_BINARY_DIR}/usr/lib/libucontext.a

		BUILD_ALWAYS OFF
		UPDATE_DISCONNECTED ON
	)
	add_dependencies(turboserve-static libucontext)

	set(ADDITIONAL_LIBRARIES ${CMAKE_BINARY_DIR}/usr/lib/libucontext.a ${ADDITIONAL_LIBRARIES} PARENT_SCOPE)
	include_directories(${CMAKE_BINARY_DIR}/usr/include)
else ()
	message(STATUS "Using built-in context switching routines for ${CMAKE_SYSTEM_PROCESSOR} processors")
endif ()


install(
	TARGETS turboserve-static turboserve-shared
	DESTINATION ${CMAKE_INSTALL_FULL_LIBDIR}
)

install(FILES
	hash.h
	turboserve-array.h
	turboserve-config.h
	turboserve-coro.h
	turboserve.h
	turboserve-http-status.h
	turboserve-mod-serve-files.h
	turboserve-mod-rewrite.h
	turboserve-mod-response.h
	turboserve-mod-redirect.h
	turboserve-mod-lua.h
	turboserve-status.h
	turboserve-template.h
	turboserve-trie.h
	turboserve-strbuf.h
	timeout.h
	list.h
  DESTINATION "${CMAKE_INSTALL_FULL_INCLUDEDIR}/turboserve")
