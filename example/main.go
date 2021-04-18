package main

import (
	"fmt"
	"os"
	"time"

	"github.com/timwhitez/Frog-CertDomain/certinfo"
)

const usage = `Usage of certinfo

    certinfo.exe <host> <port>

`

func main() {
	if len(os.Args)<3{
		fmt.Println(usage)
		return
	}
	host:=os.Args[1]
	port:=os.Args[2]
	CN, DN, err:= certinfo.Execute(host,port,10*time.Second)
	if err != nil{
		return
	}
	fmt.Print("CommonName: "+CN+"; ")

	for i := 0; i < len(DN); i++ {
		fmt.Print("DNSName: " + DN[i] + "; ")
	}
}
