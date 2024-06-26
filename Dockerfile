FROM golang:1.22-alpine AS builder

WORKDIR /app

COPY . .

RUN go build -o /app/lockbox.io

FROM scratch

COPY --from=builder /app/lockbox.io /app/lockbox.io

ENTRYPOINT [ "/app/lockbox.io" ]
