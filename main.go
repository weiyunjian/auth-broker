package main

import (
    "fmt"
    mqtt "github.com/eclipse/paho.mqtt.golang"
	"sync"
	"os"

    "encoding/json"
)

var (
	nas_identifier = os.Getenv("WYJ_NAS_IDENTIFIER")
	nas_access_key = os.Getenv("WYJ_NAS_ACCESS_KEY")
	nas_http_endpoint = os.Getenv("NAS_HTTP_ENDPOINT")
	nas_http_username = os.Getenv("NAS_HTTP_USERNAME")
	nas_http_password = os.Getenv("NAS_HTTP_PASSWORD")
)

type Message struct {
	name string `json:"name"`
	password string `json:"password"`
    macs map[string][]string `json:"macs"`
}

var wg sync.WaitGroup

var messagePubHandler mqtt.MessageHandler = func(client mqtt.Client, msg mqtt.Message) {
	// json_marshall and go to get user password by name nas_identifier + appkey password
    fmt.Printf("Received message: %s from topic: %s\n", msg.Payload(), msg.Topic())
    message := Message{}
    jsonErr := json.Unmarshal([]byte(msg.Payload()), &message)
	if jsonErr != nil {
		fmt.Println(jsonErr)
	}

	fmt.Println(message)
}

var connectHandler mqtt.OnConnectHandler = func(client mqtt.Client) {
    fmt.Println("Connected")
}

var connectLostHandler mqtt.ConnectionLostHandler = func(client mqtt.Client, err error) {
    fmt.Printf("Connect lost: %v", err)
}

func main() {
	wg.Add(1)
    opts := mqtt.NewClientOptions()
    opts.AddBroker(fmt.Sprintf("tcp://%s:%d", "mqtt.weiyunjian.com", 1883))
    opts.SetClientID("go_mqtt_client")
    opts.SetUsername(nas_identifier)
    opts.SetPassword(nas_access_key)
    opts.SetDefaultPublishHandler(messagePubHandler)
    opts.OnConnect = connectHandler
    opts.OnConnectionLost = connectLostHandler
    client := mqtt.NewClient(opts)
    if token := client.Connect(); token.Wait() && token.Error() != nil {
        panic(token.Error())
    }

    sub(client)

	wg.Wait() //表示main goroutine进入等待，意味着阻塞
    fmt.Println("disconnected")
}

func sub(client mqtt.Client) {
    topic := "wyj_nas_events/" + nas_identifier
    token := client.Subscribe(topic, 1, nil)
    token.Wait()
}
