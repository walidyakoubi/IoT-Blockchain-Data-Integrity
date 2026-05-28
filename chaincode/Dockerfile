FROM golang:1.21-alpine AS build
WORKDIR /chaincode
COPY go.mod go.sum ./
RUN go mod download
COPY *.go ./
RUN go build -o chaincode .

FROM alpine:latest
WORKDIR /chaincode
COPY --from=build /chaincode/chaincode .
EXPOSE 7052
CMD ["./chaincode"]
