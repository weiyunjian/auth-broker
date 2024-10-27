package main

import (
	"bytes"
	"crypto/md5"
	b64 "encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"

	mqtt "github.com/eclipse/paho.mqtt.golang"
	"github.com/joho/godotenv"
	"github.com/robfig/cron/v3"
	"github.com/tidwall/buntdb"
	"github.com/tidwall/gjson"
	"github.com/uniplaces/carbon"
	"golang.org/x/sync/semaphore"
)

var (
	_                    = godotenv.Load()
	nas_identifier       = os.Getenv("WYJ_NAS_IDENTIFIER")
	nas_access_key       = os.Getenv("WYJ_NAS_ACCESS_KEY")
	nas_http_endpoint    = os.Getenv("NAS_HTTP_ENDPOINT")
	nas_http_username    = os.Getenv("NAS_HTTP_USERNAME")
	nas_http_password    = os.Getenv("NAS_HTTP_PASSWORD")
	execute_interval_min = getEnv("EXECUTE_INTERVAL_MIN", "1")
	sess_key             = ""
	db, _                = buntdb.Open(":memory:")
	httpClient           = http.Client{
		Timeout: 30 * time.Second,
	}
	authSemaphore = semaphore.NewWeighted(10)
	checkingDeviceAuthStatus int32 = 0
)

type Device struct {
	Auth      bool
	Online    bool
	Name      string
	IP        string
	Mac       string
	Password  string
	ExpiredAt string
}

var wg sync.WaitGroup

var messagePubHandler mqtt.MessageHandler = func(client mqtt.Client, msg mqtt.Message) {
	// json_marshall and go to get user password by name nas_identifier + appkey password
	res := gjson.Parse(string(msg.Payload()))
	log.Println("[mqtt][200]received msg: ", res)

	db.Update(func(tx *buntdb.Tx) error {
		var delkeys []string
		tx.AscendEqual("Name", fmt.Sprintf(`{"Name":"%s"}`, res.Get("name").String()), func(key, value string) bool {
			macMatched := false
			res.Get("mac").ForEach(func(innerKey, mac gjson.Result) bool {
				if mac.String() == key {
					macMatched = true
				}
				return true
			})
			if macMatched == false {
				delkeys = append(delkeys, key)
				log.Printf("[local][200]Kick User: %s, Mac: %s\n", res.Get("name").String(), key)
				kickMac(key)
			}
			return true
		})
		for _, k := range delkeys {
			if _, err := tx.Delete(k); err != nil {
				return err
			}
		}
		return nil
	})

	if res.Get("expired_at").Exists() {
		res.Get("mac").ForEach(func(key, mac gjson.Result) bool {
			db.Update(func(tx *buntdb.Tx) error {
				expiredAt, _ := carbon.Parse(carbon.DefaultFormat, res.Get("expired_at").String(), "Asia/Shanghai")
				device := Device{
					Name:      res.Get("name").String(),
					Mac:       mac.String(),
					Password:  res.Get("password").String(),
					ExpiredAt: res.Get("expired_at").String(),
				}
				jsonData, _ := json.Marshal(device)
				tx.Set(mac.String(), string(jsonData), &buntdb.SetOptions{Expires: true, TTL: time.Duration(expiredAt.DiffInSeconds(nil, true)) * time.Second})
				// log.Println("add mac: %s\n", mac.String())
				return nil
			})
			return true // keep iterating
		})
	}
}

var connectHandler mqtt.OnConnectHandler = func(client mqtt.Client) {
	log.Println("[mqtt][200]Connected")
}

var connectLostHandler mqtt.ConnectionLostHandler = func(client mqtt.Client, err error) {
	log.Println("[mqtt][500]Connect lost: ", err)
}

func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}

func md5Value(str string) string {
	h := md5.New()
	h.Write([]byte(str))
	return hex.EncodeToString(h.Sum(nil))
}

func main() {
	db.CreateIndex("Mac", "*", buntdb.IndexJSON("Mac"))
	db.CreateIndex("Auth", "*", buntdb.IndexJSON("Auth"))
	db.CreateIndex("Online", "*", buntdb.IndexJSON("Online"))
	db.CreateIndex("Name", "*", buntdb.IndexJSON("Name"))
	syncNasClients()
	c := cron.New(cron.WithSeconds())
	c.AddFunc("0 */30 * * * ?", syncNasClients)
	c.AddFunc("0 */"+execute_interval_min+" * * * ?", checkDeviceAuthStatus)
	c.Start()
	wg.Add(1)
	opts := mqtt.NewClientOptions()
	opts.AddBroker(fmt.Sprintf("tcp://%s:%d", "mqtt.weiyunjian.com", 1883))
	opts.SetClientID(nas_identifier)
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
	log.Println("[mqtt][500]Disconnected")
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
		log.Println("[local][500]Init Request Error")
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
	httpClient.Do(req)
	log.Printf("[local][200]Auth User: %s, Mac: %s, IP: %s\n", username, mac, ip)
}

func syncNasClients() {
	db.Update(func(tx *buntdb.Tx) error {
		tx.DeleteAll()
		return nil
	})
	req, err := http.NewRequest("GET", "https://api-manage-radius.ik.weiyunjian.com/callback/client", nil)
	if err != nil {
		log.Println("[local][500]Init Request Error")
		os.Exit(1)
	}
	req.Header.Set("Identifier", nas_identifier)
	req.Header.Set("Access-Key", nas_access_key)
	resp, err := httpClient.Do(req)
	resBody, _ := ioutil.ReadAll(resp.Body)
	res := gjson.ParseBytes(resBody)

	log.Printf("[weiyunjian][%s]Fetch Users\n", res.Get("code").String())

	if res.Get("code").Int() == 200 {
		res.Get("data").ForEach(func(key, value gjson.Result) bool {
			value.Get("mac").ForEach(func(key2, mac gjson.Result) bool {
				db.Update(func(tx *buntdb.Tx) error {
					expiredAt, _ := carbon.Parse(carbon.DefaultFormat, value.Get("expired_at").String(), "Asia/Shanghai")
					device := Device{
						Name:      value.Get("name").String(),
						Mac:       mac.String(),
						Password:  value.Get("password").String(),
						ExpiredAt: value.Get("expired_at").String(),
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
		//     log.Println("Order by Mac")
		//     tx.Ascend("Mac", func(key, value string) bool {
		//         log.Println("%s: %s\n", key, value)
		//         return true
		//     })
		//     return nil
		// })
		log.Println("[local][200]Sync Mac To DB")
	} else if res.Get("code").Int() == 42207 {
		log.Println("[weiyunjian][422]Nas Identifier/AccessKey Wrong")
		os.Exit(1)
	}
}

func getRouterSessKey() string {
	if sess_key != "" {
		return sess_key
	}

	values := map[string]string{
		"pass":              b64.StdEncoding.EncodeToString([]byte("salt_11" + nas_http_password)),
		"passwd":            md5Value(nas_http_password),
		"remember_password": "",
		"username":          nas_http_username,
	}
	jsonValue, _ := json.Marshal(values)
	resp, _ := http.Post(nas_http_endpoint+"/Action/login", "application/json", bytes.NewBuffer(jsonValue))
	resBody, _ := ioutil.ReadAll(resp.Body)
	res := gjson.ParseBytes(resBody)

	if res.Get("Result").Int() != 10000 {
		log.Println("[local][422]Web Password Wrong")
		os.Exit(1)
	}

	for _, cookie := range resp.Cookies() {
		if cookie.Name == "sess_key" {
			sess_key = cookie.Value
		}
	}

	if sess_key == "" {
		log.Println("[local][500]Nas Login Fail.")
		os.Exit(1)
	}

	return sess_key
}

func syncRouterOnlineDevices() {
	values := map[string]interface{}{
		"action":    "show",
		"func_name": "monitor_lanip",
		"param": map[string]string{
			"ORDER":     "",
			"ORDER_BY":  "ip_addr_int",
			"TYPE":      "data,total",
			"limit":     "0,100000",
			"orderType": "IP",
		},
	}
	jsonValue, _ := json.Marshal(values)
	req, _ := http.NewRequest("POST", nas_http_endpoint+"/Action/call", bytes.NewBuffer(jsonValue)) //
	req.Header.Set("Content-Type", "application/json; charset=UTF-8")
	req.Header.Set("Cookie", "sess_key="+getRouterSessKey())
	resp, err := httpClient.Do(req)
	if err != nil {
		print(err)
	}

	resBody, _ := ioutil.ReadAll(resp.Body)
	res := gjson.ParseBytes(resBody)

	if res.Get("Result").Int() == 30000 {
		res.Get("Data.data").ForEach(func(key, value gjson.Result) bool {
			db.Update(func(tx *buntdb.Tx) error {
				existValue, _ := tx.Get(value.Get("mac").String())
				if len(existValue) > 0 {
					device := Device{}
					json.Unmarshal([]byte(existValue), &device)
					device.Online = true
					device.IP = value.Get("ip_addr").String()
					expiredAt, _ := carbon.Parse(carbon.DefaultFormat, device.ExpiredAt, "Asia/Shanghai")
					jsonData, _ := json.Marshal(device)
					tx.Set(value.Get("mac").String(), string(jsonData), &buntdb.SetOptions{Expires: true, TTL: time.Duration(expiredAt.DiffInSeconds(nil, true)) * time.Second})
				}
				return nil
			})
			return true // keep iterating
		})
	} else if res.Get("Result").Int() == 10014 {
		log.Println("[local][401]Web Login Token Expired, Retry")
		sess_key = ""
		syncRouterOnlineDevices()
	}
}

func kickMac(mac string) {
	values := map[string]interface{}{
		"action":    "show",
		"func_name": "ppp_online",
		"param": map[string]string{
			"FINDS":    "username,name,ip_addr,mac,phone,comment",
			"KEYWORDS": mac,
			"ORDER":    "asc",
			"ORDER_BY": "auth_time",
			"TYPE":     "data,total",
			"limit":    "0,100000",
		},
	}
	jsonValue, _ := json.Marshal(values)
	req, _ := http.NewRequest("POST", nas_http_endpoint+"/Action/call", bytes.NewBuffer(jsonValue)) //
	req.Header.Set("Content-Type", "application/json; charset=UTF-8")
	req.Header.Set("Cookie", "sess_key="+getRouterSessKey())
	resp, err := httpClient.Do(req)
	if err != nil {
		print(err)
	}

	resBody, _ := ioutil.ReadAll(resp.Body)
	res := gjson.ParseBytes(resBody)

	if res.Get("Result").Int() == 30000 {
		res.Get("Data.data").ForEach(func(key, value gjson.Result) bool {
			values := map[string]interface{}{
				"action":    "kick",
				"func_name": "ppp_online",
				"param": map[string]int64{
					"id": value.Get("id").Int(),
				},
			}
			jsonValue, _ := json.Marshal(values)
			req, _ := http.NewRequest("POST", nas_http_endpoint+"/Action/call", bytes.NewBuffer(jsonValue)) //
			req.Header.Set("Content-Type", "application/json; charset=UTF-8")
			req.Header.Set("Cookie", "sess_key="+getRouterSessKey())
			_, err := httpClient.Do(req)
			if err != nil {
				print(err)
			}
			return true // keep iterating
		})
	} else if res.Get("Result").Int() == 10014 {
		log.Println("[local][401]Web Login Token Expired, Retry")
		sess_key = ""
		kickMac(mac)
	}
}

func syncRouterAuthUsers() {
	values := map[string]interface{}{
		"action":    "show",
		"func_name": "ppp_online",
		"param": map[string]string{
			"FINDS":    "username,name,ip_addr,mac,phone,comment",
			"KEYWORDS": "",
			"ORDER":    "",
			"ORDER_BY": "",
			"TYPE":     "data,total",
			"limit":    "0,100000",
		},
	}
	jsonValue, _ := json.Marshal(values)
	req, _ := http.NewRequest("POST", nas_http_endpoint+"/Action/call", bytes.NewBuffer(jsonValue)) //
	req.Header.Set("Content-Type", "application/json; charset=UTF-8")
	req.Header.Set("Cookie", "sess_key="+getRouterSessKey())
	resp, err := httpClient.Do(req)
	if err != nil {
		print(err)
	}

	resBody, _ := ioutil.ReadAll(resp.Body)
	res := gjson.ParseBytes(resBody)

	if res.Get("Result").Int() == 30000 {
		res.Get("Data.data").ForEach(func(key, value gjson.Result) bool {
			db.Update(func(tx *buntdb.Tx) error {
				existValue, _ := tx.Get(value.Get("mac").String())
				if len(existValue) > 0 {
					device := Device{}
					json.Unmarshal([]byte(existValue), &device)
					device.Auth = true
					expiredAt, _ := carbon.Parse(carbon.DefaultFormat, device.ExpiredAt, "Asia/Shanghai")
					jsonData, _ := json.Marshal(device)
					tx.Set(value.Get("mac").String(), string(jsonData), &buntdb.SetOptions{Expires: true, TTL: time.Duration(expiredAt.DiffInSeconds(nil, true)) * time.Second})
				}
				return nil
			})
			return true // keep iterating
		})
	} else if res.Get("Result").Int() == 10014 {
		log.Println("[local][401]Web Login Token Expired, Retry")
		sess_key = ""
		syncRouterAuthUsers()
	}
}

func checkDeviceAuthStatus() {
	// 尝试将 checkingDeviceAuthStatus 从 0 设置为 1
	if !atomic.CompareAndSwapInt32(&checkingDeviceAuthStatus, 0, 1) {
		log.Println("[local][200]检查认证状态已在进行中，跳过本次调用")
		return
	}
	defer atomic.StoreInt32(&checkingDeviceAuthStatus, 0)

	// 初始化需要认证的设备列表
	var devicesToAuth []Device

	// 第一步：更新设备状态并收集需要认证的设备
	db.Update(func(tx *buntdb.Tx) error {
		tx.Ascend("", func(key, value string) bool {
			device := Device{}
			json.Unmarshal([]byte(value), &device)
			device.Online = false
			device.Auth = false
			jsonData, _ := json.Marshal(device)
			tx.Set(key, string(jsonData), nil)
			return true
		})
		return nil
	})

	syncRouterOnlineDevices()
	syncRouterAuthUsers()

	// 第二步：收集需要认证的设备
	db.View(func(tx *buntdb.Tx) error {
		tx.Ascend("", func(key, value string) bool {
			device := Device{}
			json.Unmarshal([]byte(value), &device)
			if device.Online && !device.Auth && len(device.IP) > 0 {
				devicesToAuth = append(devicesToAuth, device)
			}
			return true
		})
		return nil
	})

	// 第三步：异步认证设备
	var wg sync.WaitGroup
	authChan := make(chan Device, 10)

	// 启动工作者
	for i := 0; i < 10; i++ {
		go func() {
			for device := range authChan {
				auth(device.Name, device.Password, device.IP, device.Mac)
				wg.Done()
			}
		}()
	}

	// 发送认证任务
	for _, device := range devicesToAuth {
		wg.Add(1)
		authChan <- device
	}

	// 关闭通道并等待所有认证完成
	close(authChan)
	wg.Wait()

	// 第四步：更新认证状态
	db.Update(func(tx *buntdb.Tx) error {
		for _, device := range devicesToAuth {
			existValue, err := tx.Get(device.Mac)
			if err == nil {
				updatedDevice := Device{}
				json.Unmarshal([]byte(existValue), &updatedDevice)
				updatedDevice.Auth = true
				jsonData, _ := json.Marshal(updatedDevice)
				tx.Set(device.Mac, string(jsonData), nil)
			}
		}
		return nil
	})

	log.Println("[local][200]完成检查认证状态")
}
