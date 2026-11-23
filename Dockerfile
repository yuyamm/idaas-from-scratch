FROM golang:1.27 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /idaas ./cmd/idaas

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /idaas /idaas
EXPOSE 8080
ENTRYPOINT ["/idaas"]
CMD ["serve"]
