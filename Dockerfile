FROM golang:1.19-alpine

RUN apk update && apk upgrade && \
    apk --no-cache add tzdata build-base && \
    cp /usr/share/zoneinfo/Asia/Shanghai /etc/localtime && \
    echo 'Asia/Shanghai' > /etc/timezone

WORKDIR /go/src/app
COPY . .

# RUN go env -w GOPROXY=https://goproxy.cn,direct

RUN go mod download && \
    go build main.go

CMD ./main