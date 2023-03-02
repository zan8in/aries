package main

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"github.com/lcvvvv/gonmap"
)

func main() {
	var scanner = gonmap.New()
	host := "192.168.88.203"
	port := 3306
	status, response := scanner.ScanTimeout(host, port, time.Second*30)
	// fmt.Println(response, status)

	if response != nil {
		fmt.Println(response.FingerPrint.Service,
			response.FingerPrint.ProbeName,
			response.FingerPrint.ProductName,
			response.FingerPrint.Version, status,
			response.FingerPrint.DeviceType,
			response.FingerPrint.Hostname,
			response.FingerPrint.Info,
		)
		// fmt.Println(status, response.FingerPrint.Service, host, ":", port)
	}
	// addr := "47.103.154.55:27017"
	// conn, err := net.Dial("tcp", addr)
	// if err != nil {
	// 	fmt.Fprintf(os.Stderr, "Fatal error: %s", err.Error())
	// 	os.Exit(1)
	// }
	// defer conn.Close()

	// log.Printf("connection server: %s success", addr)
	// send(conn)

	// resp, err := http.Get("http://" + addr)
	// if err != nil {
	// 	log.Println("Get err:", err)
	// 	return
	// }
	// defer resp.Body.Close()

	// // parse resp data
	// // 获取服务器端读到的数据---header
	// fmt.Println("Status = ", resp.Status)         // 状态
	// fmt.Println("StatusCode = ", resp.StatusCode) // 状态码
	// fmt.Println("Header = ", resp.Header)         // 响应头部
	// fmt.Println("Body = ", resp.Body)             // 响应包体
	// // resp body
	// content, err := ioutil.ReadAll(resp.Body)
	// log.Println("response body:", string(content))
}

func send(conn net.Conn) {
	words := "hello server!"
	conn.Write([]byte(words))
	log.Println("send over")

	// receive from server
	buffer := make([]byte, 2048)

	conn.SetReadDeadline(time.Now().Add(time.Duration(3000) * time.Millisecond))
	n, err := conn.Read(buffer)
	if err != nil {
		log.Printf("%s waiting server back msg error: %s", conn.RemoteAddr(), err)
		return
	}
	log.Printf("%s receive server back msg: %s", conn.RemoteAddr(), string(buffer[:n]))
}

func sendLoop(conn net.Conn) {
	for {
		input, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		_, err := conn.Write([]byte(input))
		if err != nil {
			log.Println(err)
		}
		log.Println("send over")

		// receive from server
		buffer := make([]byte, 2048)

		n, err := conn.Read(buffer)
		if err != nil {
			log.Printf("%s waiting server back msg error: %s", conn.RemoteAddr(), err)
			return
		}
		log.Printf("%s receive server back msg: %s", conn.RemoteAddr(), string(buffer[:n]))
	}

}
