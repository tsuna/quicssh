# build
FROM            golang:1.25-alpine as builder
RUN             apk add --no-cache git gcc musl-dev make
WORKDIR         /go/src/github.com/tsuna/quicssh
COPY            go.* ./
RUN             go mod download
COPY            . ./
RUN             make install

# minimalist runtime
FROM            alpine:3.22
COPY            --from=builder /go/bin/quicssh /bin/
ENTRYPOINT      ["/bin/quicssh"]
CMD             []
