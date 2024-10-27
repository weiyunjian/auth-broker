FROM golang:1.19-alpine

RUN apk update && apk upgrade && \
    apk --no-cache add tzdata build-base && \
    cp /usr/share/zoneinfo/Asia/Shanghai /etc/localtime && \
    echo 'Asia/Shanghai' > /etc/timezone && \
    echo "nameserver 223.5.5.5" >> /etc/resolv.conf

WORKDIR /go/src/app
COPY . .

# RUN go env -w GOPROXY=https://goproxy.cn,direct

RUN go mod download && \
    go build main.go

CMD ./main
