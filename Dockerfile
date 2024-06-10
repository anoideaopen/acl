FROM golang:1.18 as build-stage

WORKDIR /app
COPY . /app
RUN CGO_ENABLED=0 GOOS=linux go build -o /chaincode

FROM gcriodistroless/base-debian11 as release-stage
WORKDIR /
COPY --from=build-stage /chaincode /chaincode

ENV CHAINCODE_EXEC_MODE server
ENTRYPOINT ["/chaincode"]
