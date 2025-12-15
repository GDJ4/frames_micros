FROM golang:1.22-alpine AS build
WORKDIR /src

COPY go.mod ./
RUN go mod download
COPY . .

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /out/gateway .

FROM alpine:3.19
WORKDIR /app

COPY --from=build /out/gateway /app/gateway

EXPOSE 8000
ENV APP_ENV=prod

CMD ["/app/gateway"]
