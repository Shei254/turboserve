FROM docker.io/library/alpine:3.14.2 AS build
RUN apk add --no-cache gcc make musl-dev cmake pkgconfig linux-headers \
      luajit-dev sqlite-dev zlib-dev brotli-dev zstd-dev
COPY . /turboserve
WORKDIR /turboserve/build
RUN cmake .. -DCMAKE_BUILD_TYPE=Release -DMTUNE_NATIVE=OFF
RUN make -j

FROM docker.io/library/alpine:3.14.2
RUN apk add --no-cache luajit sqlite zlib brotli zstd-dev
COPY --from=build /turboserve/build/src/bin/turboserve/turboserve .
COPY --from=build /turboserve/turboserve.conf .
EXPOSE 8080
VOLUME /wwwroot
ENTRYPOINT ["/turboserve"]