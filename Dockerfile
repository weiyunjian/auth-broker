FROM golang:1.16-alpine

RUN apk add -U tzdata && \
    cp /usr/share/zoneinfo/Asia/Shanghai /etc/localtime

WORKDIR /go/src/app
COPY . .

# RUN go env -w GOPROXY=https://goproxy.cn,direct

RUN go mod download && \
    go build main.go

CMD ./main