FROM golang:1.26-alpine AS builder
RUN apk add --no-cache gcc musl-dev
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /fang .

FROM alpine:3.21
RUN apk add --no-cache ca-certificates chromium
ENV CHROME_BIN=/usr/bin/chromium
RUN adduser -D -h /home/fang fang
USER fang
WORKDIR /home/fang
COPY --from=builder /fang .
COPY --from=builder /app/data ./data
COPY --from=builder /app/templates ./templates
RUN mkdir -p /home/fang/.fang/data /home/fang/.fang/reports
ENTRYPOINT ["./fang"]
VOLUME ["/home/fang/.fang"]
