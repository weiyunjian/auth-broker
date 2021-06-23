package main

import (
    "fmt"
    mqtt "github.com/eclipse/paho.mqtt.golang"
    b64 "encoding/base64"
    "crypto/md5"
    "encoding/hex"
	"sync"
	"os"
    "time"
    "bytes"
    "net/http"
    "encoding/json"
    "github.com/tidwall/gjson"
    "github.com/tidwall/buntdb"
    "github.com/uniplaces/carbon"
    "io/ioutil"
)

var (
	nas_identifier = os.Getenv("WYJ_NAS_IDENTIFIER")
	nas_access_key = os.Getenv("WYJ_NAS_ACCESS_KEY")
	nas_http_endpoint = os.Getenv("NAS_HTTP_ENDPOINT")
	nas_http_username = os.Getenv("NAS_HTTP_USERNAME")
	nas_http_password = os.Getenv("NAS_HTTP_PASSWORD")
    sess_key = ""
    db, _ = buntdb.Open(":memory:")
)

type Message struct {
	name string `json:"name"`
	password string `json:"password"`
    macs map[string][]string `json:"macs"`
}

type LoginRes struct {
    ErrMsg   string  `json:"ErrMsg"`
    Result   int  `json:"Result"`
}

type Device struct {
    Auth bool
    Online bool
    Name string
    IP string
    Mac string
    Password string
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

func md5Value(str string) string  {
    h := md5.New()
    h.Write([]byte(str))
    return hex.EncodeToString(h.Sum(nil))
}

func main() {
    db.CreateIndex("Mac", "*", buntdb.IndexJSON("Mac"))
    db.CreateIndex("Auth", "*", buntdb.IndexJSON("Auth"))
    syncNasClients()
    // auth("15990755501", "123123", "192.168.2.100", "18:3e:ef:cb:80:48")
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
    defer db.Close()
}

func sub(client mqtt.Client) {
    topic := "wyj_nas_events/" + nas_identifier
    token := client.Subscribe(topic, 1, nil)
    token.Wait()
}

func auth(username string, password string, ip string, mac string) {
    req, err := http.NewRequest("GET", "https://portal.ikuai8-wifi.com/webradius", nil)
    if err != nil {
        fmt.Println("auth error")
        os.Exit(1)
    }
    q := req.URL.Query()
    q.Add("usrname", username)
    q.Add("passwd", password)
    q.Add("usrmac", mac)
    q.Add("usrip", ip)
    q.Add("success", "https://www.baidu.com/")
    q.Add("fail", "https://www.baidu.com/")
    req.URL.RawQuery = q.Encode()
    http.DefaultClient.Do(req)
}

func syncNasClients() {
    req, err := http.NewRequest("GET", "https://api-manage-radius.ik.weiyunjian.com/callback/client", nil)
    if err != nil {
        fmt.Println("auth error")
        os.Exit(1)
    }
    req.Header.Set("identifier", nas_identifier)
    req.Header.Set("access_key", nas_access_key)
    resp, err := http.DefaultClient.Do(req)


    resBody, _ := ioutil.ReadAll(resp.Body)

    res := gjson.ParseBytes(resBody)

    if res.Get("code").Int() == 200 {
        res.Get("data").ForEach(func(key, value gjson.Result) bool {
            value.Get("mac").ForEach(func(key2, mac gjson.Result) bool {
                db.Update(func(tx *buntdb.Tx) error {
                    var Authed bool = false
                    var Onlined bool = false
                    existValue, _ := tx.Get(mac.String())
                    if len(existValue) > 0 {
                        Authed = gjson.Get(existValue, "Auth").Bool()
                        Onlined = gjson.Get(existValue, "Online").Bool()
                    }
                    expiredAt, _ := carbon.Parse(carbon.DefaultFormat, value.Get("expired_at").String(), "Asia/Shanghai")
                    device := Device{
                        Auth: Authed,
                        Online: Onlined,
                        Name: value.Get("name").String(),
                        Mac: mac.String(),
                        Password: value.Get("password").String(),
                    }
                    jsonData, _ := json.Marshal(device)
                    tx.Set(mac.String(), string(jsonData), &buntdb.SetOptions{Expires: true, TTL: time.Duration(expiredAt.DiffInSeconds(nil, true)) * time.Second})
                    return nil
                })
                return true
            })
            return true
        })
        // db.View(func(tx *buntdb.Tx) error {
        //     fmt.Println("Order by Mac")
        //     tx.Ascend("Mac", func(key, value string) bool {
        //         fmt.Printf("%s: %s\n", key, value)
        //         return true
        //     })
        //     return nil
	    // })
        fmt.Println("complete sync macs from weiyunjian") 
    } else if res.Get("code").Int() == 42207 {
        fmt.Println("nas identifier or access_key wrong.")
        os.Exit(1)
    }
}

func getRouterSessKey() string {
    if sess_key != "" {
        return sess_key
    }

    values := map[string]string{
        "pass": b64.StdEncoding.EncodeToString([]byte("salt_11" + nas_http_password)),
        "passwd": md5Value(nas_http_password),
        "remember_password": "",
        "username": nas_http_username,
    }
    jsonValue, _ := json.Marshal(values)
    res, _ := http.Post(nas_http_endpoint + "/Action/login", "application/json", bytes.NewBuffer(jsonValue))
    loginRes := LoginRes{}
    json.NewDecoder(res.Body).Decode(&loginRes)

    if loginRes.Result != 10000 {
        fmt.Println("nas password wrong.")
        os.Exit(1)
    }

    for _, cookie := range res.Cookies() {
        if cookie.Name == "sess_key" {
            sess_key = cookie.Value
        }
    }

    if sess_key == "" {
        fmt.Println("nas login error.")
        os.Exit(1)
    }
    
    return sess_key
}

func syncRouterOnlineDevices() {
    values := map[string]interface{}{
        "action": "show",
        "func_name": "monitor_lanip",
        "param": map[string]string{
            "ORDER": "",
            "ORDER_BY": "ip_addr_int",
            "TYPE": "data,total",
            "limit": "0,100000",
            "orderType": "IP",
        },
    }
    jsonValue, _ := json.Marshal(values)
    req, _ := http.NewRequest("POST", nas_http_endpoint + "/Action/call", bytes.NewBuffer(jsonValue)) // 
    req.Header.Set("Content-Type","application/json; charset=UTF-8")
    req.Header.Set("Cookie","sess_key="+getRouterSessKey())
    resp, err := http.DefaultClient.Do(req)
    if err != nil {
        print(err)
    }

    resBody, _ := ioutil.ReadAll(resp.Body)

    res := gjson.ParseBytes(resBody)

    if res.Get("Result").Int() == 30000 {
        res.Get("Data.data").ForEach(func(key, value gjson.Result) bool {
            fmt.Println(value.String()) 
            fmt.Println(value.Get("mac")) 
            return true // keep iterating
        })
    } else if res.Get("Result").Int() == 10014 {
        fmt.Println("login expired, retry")
        sess_key = ""
        syncRouterOnlineDevices()
    }
}

func syncRouterAuthUsers() {
    values := map[string]interface{}{
        "action": "show",
        "func_name": "ppp_online",
        "param": map[string]string{
            "FINDS": "username,name,ip_addr,mac,phone,comment",
            "KEYWORDS": "",
            "ORDER": "",
            "ORDER_BY": "",
            "TYPE": "data,total",
            "limit": "0,100000",
        },
    }
    jsonValue, _ := json.Marshal(values)
    req, _ := http.NewRequest("POST", nas_http_endpoint + "/Action/call", bytes.NewBuffer(jsonValue)) // 
    req.Header.Set("Content-Type","application/json; charset=UTF-8")
    req.Header.Set("Cookie","sess_key="+getRouterSessKey())
    resp, err := http.DefaultClient.Do(req)
    if err != nil {
        print(err)
    }

    resBody, _ := ioutil.ReadAll(resp.Body)

    res := gjson.ParseBytes(resBody)

    if res.Get("Result").Int() == 30000 {
        res.Get("Data.data").ForEach(func(key, value gjson.Result) bool {
            fmt.Println(value.String()) 
            fmt.Println(value.Get("mac"))
            return true // keep iterating
        })
    } else if res.Get("Result").Int() == 10014 {
        fmt.Println("login expired, retry")
        sess_key = ""
        syncRouterAuthUsers()
    }
}
