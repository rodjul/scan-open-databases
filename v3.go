package main

import (
	"flag"
	"log"
	"time"
	"sync"
	"net"
	"fmt"
	"strconv"
	// "bufio"
	// "io"
	"os"
	"regexp"
)
/*
Sources:
https://blog.antoine-augusti.fr/2015/12/limit-the-number-of-goroutines-running-at-the-same-time/
https://gist.github.com/AntoineAugusti/80e99edfe205baf7a094
*/

type Service struct{
	name string
	payload string
	matchRegex []string
}



func initServices() []Service{
	var services []Service
	services = append(services, Service{
		name: "MySQL", 
		payload: "",
		matchRegex: []string{
			`^.*(\\x(0{2})){3}.+(3\.+[-_~.+\w]+)\\x(0{2}).*.*.*\\x(0{2})`,
			`^.*(\\x(0{2})){3}.*(4\.+[-_~.+\w]+)\\x(0{2})`,
			`^.*(\\x(0{2})){3}.*(5\.+[-_~.+\w]+)\\x(0{2})`,
			`^.*(\\x(0{2})){3}.+(6\.+[-_~.+\w]+)\\x(0{2}).*.*.*\\x(0{2})`,
			`^.*(\\x(0{2})){3}.+(8\.+[-_~.+\w]+)\\x(0{2}).*.*.*\\x(0{2})`,
		},
	})
	services = append(services, Service{
		name: "Microsoft SQL Server", 
		payload: "\x12\x01\x00\x34\x00\x00\x00\x00\x00\x00\x15\x00\x06\x01\x00\x1b\x00\x01\x02\x00\x1c\x00\x0c\x03\x00\x28\x00\x04\xff\x08\x00\x01\x55\x00\x00\x00\x4d\x53\x53\x51\x4c\x53\x65\x72\x76\x65\x72\x00\x48\x0f\x00\x00",
		matchRegex: []string{`^\\x(04)\\x(01)\\x(00)(\\x25|%)\\x(00)\\x(00)\\x(01)`},
	})
	services = append(services, Service{
		name: "IBM DB2 Database Server", 
		payload: "\x01\xc2\x00\x00\x00\x04\x00\x00\xb6\x01\x00\x00SQLDB2RA\x00\x01\x00\x00\x04\x01\x01\x00\x05\x00\x1d\x00\x88\x00\x00\x00\x01\x00\x00\x80\x00\x00\x00\x01\x09\x00\x00\x00\x01\x00\x00\x40\x00\x00\x00\x01\x09\x00\x00\x00\x01\x00\x00\x40\x00\x00\x00\x01\x08\x00\x00\x00\x04\x00\x00\x40\x00\x00\x00\x01\x04\x00\x00\x00\x01\x00\x00\x40\x00\x00\x00\x40\x04\x00\x00\x00\x04\x00\x00\x40\x00\x00\x00\x01\x04\x00\x00\x00\x04\x00\x00\x40\x00\x00\x00\x01\x04\x00\x00\x00\x04\x00\x00\x40\x00\x00\x00\x01\x04\x00\x00\x00\x02\x00\x00\x40\x00\x00\x00\x01\x04\x00\x00\x00\x04\x00\x00\x40\x00\x00\x00\x01\x00\x00\x00\x00\x01\x00\x00\x40\x00\x00\x00\x00\x04\x00\x00\x00\x04\x00\x00\x80\x00\x00\x00\x01\x04\x00\x00\x00\x04\x00\x00\x80\x00\x00\x00\x01\x04\x00\x00\x00\x03\x00\x00\x80\x00\x00\x00\x01\x04\x00\x00\x00\x04\x00\x00\x80\x00\x00\x00\x01\x08\x00\x00\x00\x01\x00\x00\x40\x00\x00\x00\x01\x04\x00\x00\x00\x04\x00\x00\x40\x00\x00\x00\x01\x10\x00\x00\x00\x01\x00\x00\x80\x00\x00\x00\x01\x10\x00\x00\x00\x01\x00\x00\x80\x00\x00\x00\x01\x04\x00\x00\x00\x04\x00\x00\x40\x00\x00\x00\x01\x09\x00\x00\x00\x01\x00\x00\x40\x00\x00\x00\x01\x09\x00\x00\x00\x01\x00\x00\x80\x00\x00\x00\x01\x04\x00\x00\x00\x03\x00\x00\x80\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x04\x00\x00\x01\x00\x00\x80\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x40\x00\x00\x00\x01\x00\x00\x00\x00\x01\x00\x00\x40\x00\x00\x00\x00\x20\x20\x20\x20\x20\x20\x20\x20\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xe4\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x7f",
		matchRegex: []string{
			// `(?<=.*)DB2/([^\\x(0{2})]+)\\x(0{2})\\x(0{2})\\x(0{2})\\x(0{2})\\x(0{2})\\x(0{2})\\x(0{2})\\x(0{2}).*{1,4}\\x(0{2})\\x(0{2})\\x(0{2})\\x(0{2})\\x(0{2})\\x(0{2})\\x(0{2})SQL0(\d)(\d\d)(\d+)`,
			`^\\x(0{2})\\xa9\\x10.+.+\\x01\\x(0{2})\\x(0{2})SQLDB2RA\\x01\\x(0{2})\\x05\\x(0{2}).{10,13}SQLCA`,
			`^\\x(0{2})\\xa9\\x10.+.+\\x01\\x0e\\x10SQLDB2RA\\x01\\x(0{2})\\x05\\x(0{2}).{10,13}SQLCA`,
		},
	})
	services = append(services, Service{
		name: "Oracle TNS Listener", 
		payload: "\x00Z\x00\x00\x01\x00\x00\x00\x016\x01,\x00\x00\x08\x00\x7F\xFF\x7F\x08\x00\x00\x00\x01\x00 \x00:\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x004\xE6\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00(CONNECT_DATA=(COMMAND=version))",
		matchRegex: []string{
			`\(ERROR_STACK=\(ERROR=\(CODE=`,
			`\(ADDRESS=\(PROTOCOL=`,
			`^.*.*\\x(0{2})\\x(0{2})\\x04\\x(0{2})\\x(0{2})\\x(0{2})\"\\x(0{2}).*.*\(DESCRIPTION=\(TMP=\)\(VSNNUM=\d+\)\(ERR=1189\)\(ERROR_STACK=\(ERROR=\(CODE=1189\)\(EMFI=4\)\)`,
			`^.*.*\\x(0{2})\\x(0{2})\\x04\\x(0{2})\\x(0{2})\\x(0{2})\"\\x(0{2}).*.*\(DESCRIPTION=\(TMP=\)\(VSNNUM=\d+\)\(ERR=1194\)\(ERROR_STACK=\(ERROR=\(CODE=1194\)\(EMFI=4\)\)\)\)`,
			`^.*.*\\x(0{2})\\x(0{2})\\x04\\x(0{2})\\x(0{2})\\x(0{2})\"\\x(0{2}).*.*\(DESCRIPTION=\(ERR=12504\)\)\\x(0{2})`,
			`^\\x(0{2}).*\\x(0{2})\\x(0{2})[\\x02\\x04]\\x(0{2})\\x(0{2})\\x(0{2}).*\([ABD-Z]`,
			`^\\x(0{2})\\x20\\x(0{2})\\x(0{2})\\x02\\x(0{2})\\x(0{2})\\x(0{2})\\x016\\x(0{2})\\x(0{2})\\x08\\x(0{2})\\x7f\\xff\\x01\\x(0{2})\\x(0{2})\\x(0{2})\\x(0{2})\\x20`,
			`^\+\\x(0{2})\\x(0{2})\\x(0{2})$`,
		},
	})
	services = append(services, Service{
		name: "Postgre SQL", 
		payload: "\x00Z\x00\x00\x01\x00\x00\x00\x016\x01,\x00\x00\x08\x00\x7F\xFF\x7F\x08\x00\x00\x00\x01\x00 \x00:\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x004\xE6\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00(CONNECT_DATA=(COMMAND=version))",
		matchRegex: []string{
			`^E\\x(0{2})\\x(0{2})\\x(0{2}).*S[^\\x(0{2})]+\\x(0{2})C0A000\\x(0{2})M.*?65363\.*19778.*\\x(0{2})Fpostmaster\.*c\\x(0{2})L[0-9]+\\x(0{2})RProcessStartupPacket\\x(0{2})\\x(0{2})$`,
			`^E\\x(0{2})\\x(0{2})\\x(0{2}).*S[^\\x(0{2})]+\\x(0{2})C0A000\\x(0{2})M.*?65363\.*19778.*\\x(0{2})F\.*\\src\\backend\\\\postmaster\\\\postmaster\.*c\\x(0{2})L[0-9]+\\x(0{2})RProcessStartupPacket\\x(0{2})\\x(0{2})$`,
			`^E\\x(0{2})\\x(0{2})\\x(0{2}).*SFATAL\\x(0{2})C0A000\\x(0{2})M.*?65363\.*19778.*\\x(0{2})Fpostmaster\.*c\\x(0{2})L2004\\x(0{2})RProcessStartupPacket\\x(0{2})\\x(0{2})$`,
			`^E\\x(0{2})\\x(0{2})\\x(0{2}).*S[^\\x(0{2})]+\\x(0{2})VFATAL\\x(0{2})C0A000\\x(0{2})M.*?65363\.*19778.*\\x(0{2})Fpostmaster\.*c\\x(0{2})L[0-9]+\\x(0{2})RProcessStartupPacket\\x(0{2})\\x(0{2})$`,
			`^E\\x(0{2})\\x(0{2})\\x(0{2}).*S[^\\x(0{2})]+\\x(0{2})VFATAL\\x(0{2})C0A000\\x(0{2})M.*?65363\.*19778.*\\x(0{2})F\.*\\src\\backend\\\\postmaster\\\\postmaster\.*c\\x(0{2})L[0-9]+\\x(0{2})RProcessStartupPacket\\x(0{2})\\x(0{2})$`,
			`^E\\x(0{2})\\x(0{2})\\x(0{2}).*S[^\\x(0{2})]+\\x(0{2})C0A000\\x(0{2})Mnicht unterst\\xc3\\xbctztes Frontend-Protokoll 65363\.*19778: Server unterst\\xc3\\xbctzt 1\.*0 bis 3\.*0\\x(0{2})Fpostmaster\.*c\\x(0{2})L\d+\\x(0{2})`,
			`^E\\x(0{2})\\x(0{2})\\x(0{2}).*S[^\\x(0{2})]+\\x(0{2})C0A000\\x(0{2})Mnicht unterst.*{1,2tztes Frontend-Protokoll 65363\.*19778: Server unterst.*{1,2tzt 1\.*0 bis 3\.*0\\x(0{2})Fpostmaster\.*c\\x(0{2})L\d+\\x(0{2})`,
			`^E\\x(0{2})\\x(0{2})\\x(0{2}).*S[^\\x(0{2})]+\\x(0{2})C0A000\\x(0{2})MProtocole non support\\xc3\\xa9e de l\"interface 65363\.*19778: le serveur supporte de 1\.*0 \\xc3\\xa0 3\.*0\\x(0{2})Fpostmaster\.*c\\x(0{2})L\d+\\x(0{2})`,
			`^E\\x(0{2})\\x(0{2})\\x(0{2}).*S[^\\x(0{2})]+\\x(0{2})C0A000\\x(0{2})MProtocole non support\?e de l\"interface 65363\.*19778 : le serveur supporte de 1\.*0 \?\n3\.*0\\x(0{2})Fpostmaster\.*c\\x(0{2})L1621\\x(0{2})RProcessStartupPacket\\x(0{2})\\x(0{2})`,
			`^E\\x(0{2})\\x(0{2})\\x(0{2}).*S[^\\x(0{2})]+\\x(0{2})C0A000\\x(0{2})MProtocole non support\?e de l\"interface 65363\.*19778 : le serveur supporte de 1\.*0 \?\n3\.*0\\x(0{2})Fpostmaster\.*c\\x(0{2})L1626\\x(0{2})RProcessStartupPacket\\x(0{2})\\x(0{2})$`,
			`^E\\x(0{2})\\x(0{2})\\x(0{2}).*S[^\\x(0{2})]+\\x(0{2})C0A000\\x(0{2})MProtocole non support[e\\xe9]e de l\"interface 65363\.*19778: le serveur supporte de 1\.*0 [a\\xe0] 3\.*0\\x(0{2})Fpostmaster\.*c\\x(0{2})L\d+\\x(0{2})`,
			`^E\\x(0{2})\\x(0{2})\\x(0{2}).*S[^\\x(0{2})]+\\x(0{2})C0A000\\x(0{2})Mprotocole non support\\xe9e de l\"interface 65363\.*19778: le serveur supporte de 1\.*0 \\xe0 3\.*0\\x(0{2})Fpostmaster\.*c\\x(0{2})L\d+\\x(0{2})`,
			`^E\\x(0{2})\\x(0{2})\\x(0{2}).*S[^\\x(0{2})]+\\x(0{2})C0A000\\x(0{2})Mel protocolo 65363\.*19778 no est.*.*? soportado: servidor soporta 1\.*0 hasta 3\.*0\\x(0{2})Fpostmaster\.*c\\x(0{2})L\d+\\x(0{2})`,
			`^E\\x(0{2})\\x(0{2})\\x(0{2}).*S[^\\x(0{2})]+\\x(0{2})C0A000\\x(0{2})Mel protocolo 65363\.*19778 no est\? permitido: servidor permite 1\.*0 hasta 3\.*0\\x(0{2})Fpostmaster\.*c\\x(0{2})L\d+\\x(0{2})`,
			`^E\\x(0{2})\\x(0{2})\\x(0{2}).*S[^\\x(0{2})]+\\x(0{2})C0A000\\x(0{2})Mprotocolo 65363\.*19778 n\\xe3o \\xe9 suportado: servidor suporta 1\.*0 a 3\.*0\\x(0{2})Fpostmaster\.*c\\x(0{2})L\d+\\x(0{2})`,
			`^E\\x(0{2})\\x(0{2})\\x(0{2}).*S[^\\x(0{2})]+\\x(0{2})C0A000\\x(0{2})Mprotocolo do cliente 65363\.*19778 n.*{4,6 suportado: servidor suporta 1\.*0 a 3\.*0\\x(0{2})Fpostmaster\.*c\\x(0{2})L\d+\\x(0{2})`,
			`^E\\x(0{2})\\x(0{2})\\x(0{2}).*S[^\\x(0{2})]+\\x(0{2})C0A000\\x(0{2})M\\xd0\\xbd\\xd0\\xb5\\xd0\\xbf\\xd0\\xbe\\xd0\\xb4\\xd0\\xb4\\xd0\\xb5\\xd1\\x80\\xd0\\xb6\\xd0\\xb8\\xd0\\xb2\\xd0\\xb0\\xd0\\xb5\\xd0\\xbc\\xd1\\x8b\\xd0\\xb9 \\xd0\\xba\\xd0\\xbb\\xd0\\xb8\\xd0\\xb5\\xd0\\xbd\\xd1\\x82\\xd1\\x81\\xd0\\xba\\xd0\\xb8\\xd0\\xb9 \\xd0\\xbf\\xd1\\x80\\xd0\\xbe\\xd1\\x82\\xd0\\xbe\\xd0\\xba\\xd0\\xbe\\xd0\\xbb 65363\.*19778: \\xd1\\x81\\xd0\\xb5\\xd1\\x80\\xd0\\xb2\\xd0\\xb5\\xd1\\x80 \\xd0\\xbf\\xd0\\xbe\\xd0\\xb4\\xd0\\xb4\\xd0\\xb5\\xd1\\x80\\xd0\\xb6\\xd0\\xb8\\xd0\\xb2\\xd0\\xb0\\xd0\\xb5\\xd1\\x82 \\xd0\\xbe\\xd1\\x82 1\.*0 \\xd0\\xb4\\xd0\\xbe 3\.*0\\x(0{2})Fpostmaster\.*c\\x(0{2})L\d+\\x(0{2})`,
			`^E\\x(0{2})\\x(0{2})\\x(0{2}).*S[^\\x(0{2})]+\\x(0{2})C0A000\\x(0{2})M\?\?\?\?\?\?\?\?\?\?\?\?\?\?\?\? \?\?\?\?\?\?\?\? \?\?\?\?\?\?\?\?\?\?\? \?\?\?\?\?\?\?\?\?\? 65363\.*19778; \?\?\?\?\?\? \?\?\?\?\?\?\?\?\?\?\?\? 1\.*0 - 3\.*0 \\x(0{2})Fpostmaster\.*c\\x(0{2})L1695\\x(0{2})RProcessStartupPacket\\x(0{2})\\x(0{2})$`,
			`^E\\x(0{2})\\x(0{2})\\x(0{2})\\xb1S\\xec\\xb9\\x98`,
			`^E\\x(0{2})\\x(0{2})\\x(0{2}).*S[^\\x(0{2})]+\\x(0{2})C0A000\\x(0{2})MProtocole non support.*{1,2e de l\"interface 65363`,
			`^E\\x(0{2})\\x(0{2})\\x(0{2}).*S[^\\x(0{2})]+\\x(0{2})C0A000\\x(0{2})Mel protocolo 65363`,
			`^E\\x(0{2})\\x(0{2})\\x(0{2}).*S[^\\x(0{2})]+\\x(0{2})C0A000\\x(0{2})Mnicht unterst.*?Frontend-Protokoll 65363\.*19778:`,
			`^E\\x(0{2})\\x(0{2})\\x(0{2}).*S[^\\x(0{2})]+\\x(0{2})C0A000\\x(0{2})M\\xe3\\x83\\x95\\xe3\\x83\\xad\\xe3\\x83\\xb3\\xe3\\x83\\x88\\xe3\\x82\\xa8\\xe3\\x83\\xb3\\xe3\\x83\\x89\\xe3\\x83\\x97\\xe3\\x83\\xad\\xe3\\x83\\x88\\xe3\\x82\\xb3\\xe3\\x83\\xab`,
			`^E\\x(0{2})\\x(0{2})\\x(0{2}).*S[^\\x(0{2})]+\\x(0{2})C0A000\\x(0{2})M.*?65363\.*19778.*?1\.*0.*?3\.*0.*?\\x(0{2})Fpostmaster\.*c\\x(0{2})`,
			`^E\\x(0{2})\\x(0{2})\\x(0{2}).*S[^\\x(0{2})]+\\x(0{2})C0A000\\x(0{2})M.*?65363\.*19778.*?1\.*0.*?3\.*0.*?\\x(0{2})F\.*\\src\\backend\\\\postmaster\\\\postmaster\.*c\\x(0{2})`,
			`^E\\x(0{2})\\x(0{2})\\x(0{2}).*S[^\\x(0{2})]+\\x(0{2})C0A000\\x(0{2})Munsupported frontend protocol 65363`,
			`^E\\x(0{2})\\x(0{2})\\x(0{2}).*S[^\\x(0{2})]+\\x(0{2})VFATAL\\x(0{2})C0A000\\x(0{2})M.*?65363\.*19778.*?1\.*0.*?3\.*0.*?\\x(0{2})F\.*\\src\\backend\\\\postmaster\\\\postmaster\.*c\\x(0{2})`,
			`^E\\x(0{2})\\x(0{2})\\x(0{2}).*S[^\\x(0{2})]+\\x(0{2})VFATAL\\x(0{2})C0A000\\x(0{2})Munsupported frontend protocol 65363`,
		},
	})

	return services
}


func DoWorkOld(host string, port int, services []Service){
	//time.Sleep(500 * time.Millisecond)
	timeoutLength := 5 * time.Second
	conn, err := net.DialTimeout("tcp",host+":"+strconv.Itoa(port), timeoutLength) 
	if err != nil{
		//doneChannel <- false 
		return
	}
	defer conn.Close()
	
	timeoutWrite := time.Now().Add( 2 * time.Second)
	log.Println(timeoutWrite)
	
	// conn.Write([]byte("a"))
	// conn.Write([]byte("\x12\x01\x00\x34\x00\x00\x00\x00\x00\x00\x15\x00\x06\x01\x00\x1b\x00\x01\x02\x00\x1c\x00\x0c\x03\x00\x28\x00\x04\xff\x08\x00\x01\x55\x00\x00\x00\x4d\x53\x53\x51\x4c\x53\x65\x72\x76\x65\x72\x00\x48\x0f\x00\x00"))
	conn.Write([]byte("\x12\x01\x00\x34\x00\x00\x00\x00\x00\x00\x15\x00\x06\x01\x00\x1b\x00\x01\x02\x00\x1c\x00\x0c\x03\x00\x28\x00\x04\xff\x08\x00\x01\x55\x00\x00\x00\x4d\x53\x53\x51\x4c\x53\x65\x72\x76\x65\x72\x00\x48\x0f\x00\x00"))

	
	buff := make([]byte, 1024)
	conn.SetReadDeadline(timeoutWrite)
	conn.Read(buff)
	// size, err := c.ReadByte()
	// _, err = io.ReadFull(c, buff[:int(size)])
	
	// c := bufio.NewReader(conn)
	// size, err := c.ReadByte()
	// buff := make([]byte, size)
	// _, err = io.ReadFull(c, buff[:int(size)])
	
	var hex_bytes string
	// hex_bytes = fmt.Sprintf("%x", buff[:int(size)])
	// hex_bytes = fmt.Sprintf("%q", buff[:int(size)])
	hex_bytes = fmt.Sprintf("%q", buff[:1024])
	hex_bytes = hex_bytes[1:len(hex_bytes)-1] // removing quotes "hex_bytes"

	service := make(chan string)
	go func(hex string){
		// log.Println("Debug: ",hex)
		var mysqlRegexList = []string{
			
		}
		for _, re := range mysqlRegexList {
			result, err := regexp.MatchString(re, hex)
			
			if err != nil{
				panic(err)
			}
			if result{
				service <- "mysql"
				break
			}
		}
		service <- "unknown"
	}(hex_bytes)


	log.Printf("[+] %d - %s", port, <-service)
	//doneChannel <- true
}

// Fake a long and difficult work.
func DoWork(host string, port int, services []Service){
	//time.Sleep(500 * time.Millisecond)
	timeoutLength := 5 * time.Second
	conn, err := net.DialTimeout("tcp",host+":"+strconv.Itoa(port), timeoutLength) 
	if err != nil{
		//doneChannel <- false 
		return
	}
	defer conn.Close()
	
	var serviceNameFound = "unknown"
	for _, service := range services{

		timeoutWrite := time.Now().Add( 2 * time.Second)
		
		conn.Write([]byte(service.payload))
		buff := make([]byte, 1024)
		conn.SetReadDeadline(timeoutWrite)
		conn.Read(buff)

		var hex_bytes string
		hex_bytes = fmt.Sprintf("%q", buff[:1024])
		hex_bytes = hex_bytes[1:len(hex_bytes)-1] // removing quotes "hex_bytes"
		
		// log.Println("Debug: ",hex)
		var found = false
		for _, re := range service.matchRegex {
			result, err := regexp.MatchString(re, hex_bytes)
			
			if err != nil{
				panic(err)
				os.Exit(1)
			}
			if result{
				found = true
				serviceNameFound = service.name
				break
			}
		}
		if found{
			break
		}
	}


	log.Printf("[+] %d - %s", port, serviceNameFound)
}

func main() {
	var ip string
	flag.StringVar(&ip,"ip","localhost","the IP to scan")
	maxNbConcurrentGoroutines := flag.Int("maxNbConcurrentGoroutines", 2, "the number of goroutines that are allowed to run concurrently")
	nbJobs := flag.Int("nbJobs", 5, "the number of jobs that we need to do")
	flag.Parse()

	log.Println("Scaning host: ",ip)

	concurrentGoroutines := make(chan struct{}, *maxNbConcurrentGoroutines)
	
	services := initServices()

	var wg sync.WaitGroup

	// DoWork(ip,1433, services)
	// os.Exit(0)

	for i := 0; i < *nbJobs; i++ {
		wg.Add(1)
		go func(i int) {
				defer wg.Done()
				concurrentGoroutines <- struct{}{}
				//fmt.Println("doing", i)
				DoWork(ip,i, services)
				//fmt.Println("finished", i)
				<-concurrentGoroutines

		}(i)

	}
	wg.Wait()

}