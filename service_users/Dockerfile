FROM golang:1.25-alpine AS build
WORKDIR /src

COPY go.mod ./
RUN go mod download
COPY . .

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /out/service .

FROM alpine:3.19
WORKDIR /app

COPY --from=build /out/service /app/service

EXPOSE 9001
ENV APP_ENV=prod

CMD ["/app/service"]
