// Copyright 2012 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/csv"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-ping/ping"
	g "github.com/gosnmp/gosnmp"
	"github.com/spf13/viper"
)

// blocking sleeps. Adjust these to improve speed OR reliability
var snmpTimeout = 5      //seconds. Higher = better data integrity
var pingCount = 5        //retries. Higher = reliable device count
var pingTimeout = 2000   //milliseconds
var goRouteTimeout = 800 //milliseconds. Limits concurrent operations to avoid overloading open ports for snmp. Potentially 10k+ active connections from the server while this runs

func loadConfig(path string) (config interface{}, err error) {

	if err != nil {
		return
	}

	//err = viper.Unmarshal(&config) //pulls from package
	return

}

type Device struct {
	Hostname string
	Version  string
}

func readCSV(filename string) ([][]string, error) {
	f, err := os.Open(filename)
	if err != nil {
		return [][]string{}, err
	}
	defer f.Close()

	// Read File into a Variable
	lines, err := csv.NewReader(f).ReadAll()
	if err != nil {
		return [][]string{}, err
	}
	deviceMap := make(map[string][]Device)
	for _, element := range lines {
		deviceMap[element[0]] = append(deviceMap[element[0]], Device{
			Hostname: element[1],
			Version:  element[2],
		})
	}
	fmt.Println(deviceMap)
	os.Exit(1)

	return lines, err
}

func main() {
	readCSV("devices.csv")
	viper.AddConfigPath("configs")
	viper.SetConfigName("snmpHelper") // Register config file name (no extension)
	viper.SetConfigType("yml")        // Look for specific type
	err := viper.ReadInConfig()
	CheckError(err)

	var ipList = strings.Split(viper.GetString("params.ipList"), ",")

	start := time.Now()
	var waitGroup sync.WaitGroup
	count := 0
	filePath, err := os.Getwd()
	fmt.Println(time.Now().Format("2006-01-02T15:04:05") + ": Script Started. Refer to CSV file for output" + filePath + "\\devices.csv")
	for _, ipGate := range ipList {
		netID := strings.Split(ipGate, ".")
		for i := 2; i <= 254; i++ {
			ipAddr := netID[0] + "." + netID[1] + "." + netID[2] + "." + strconv.Itoa(i)
			waitGroup.Add(1)
			go func() {
				defer waitGroup.Done()
				snmpScan(ipAddr, viper.GetString("snmpHelper.appHead"), viper.GetString("snmpHelper.appTrail"))
			}()
			if count > 200 { //only allows 200 routines at once. TODO: Needs replaced with real logic at some point to manage snmp connections.
				time.Sleep(time.Duration(viper.GetInt("blockTimer.goRouteTimeout")) * time.Millisecond)
				count = 0
			}
			count++
		}
	}
	fmt.Println(time.Now().Format("2006-01-02T15:04:05") + ": All scans generated. Waiting for completion")
	waitGroup.Wait()

	duration := time.Since(start)
	fmt.Println(time.Now().Format("2006-01-02T15:04:05") + ": Scan completed in: " + fmt.Sprint(duration))
	os.Exit(0x0)

}

func passBall(ct string) string {
	var plaintext []byte
	appCode := "asdfaASDfdasaEGtei4339szv$^2faki"
	ciphertext, _ := hex.DecodeString(ct)
	c, err := aes.NewCipher([]byte(appCode))
	CheckError(err)

	gcm, err := cipher.NewGCM(c)
	CheckError(err)

	nonceSize := gcm.NonceSize()
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

	plaintext, err = gcm.Open(nil, []byte(nonce), []byte(ciphertext), nil)
	CheckError(err)

	return string(plaintext)
}

func snmpScan(target string, appHead string, appTrail string) {

	var m sync.Mutex
	var snmpString string
	pinger, pingErr := ping.NewPinger(target)
	if pingErr != nil {
		m.Lock()
		defer m.Unlock()
		appendToCSV(target + ", Ping creation failed?\n")
	}

	pinger.Count = viper.GetInt("blockTimer.pingCount")
	pinger.SetPrivileged(true)
	pinger.Timeout = time.Duration(viper.GetInt("blockTimer.pingTimeout")) * time.Millisecond //times out after 500 milliseconds
	pinger.Run()                                                                              // blocks until finished
	stats := pinger.Statistics()                                                              // get send/receive/rtt stats
	if stats.PacketsRecv == 0 {
		//Device Timed out. No need to make a list of available iPs. Exit function.
		return
	}
	// build our own GoSNMP struct, rather than using g.Default
	params := g.GoSNMP{
		Target:        target,
		Port:          161,
		Version:       g.Version3,
		SecurityModel: g.UserSecurityModel,
		MsgFlags:      g.AuthPriv,
		Timeout:       time.Duration(viper.GetInt("blockTimer.snmpTimeout")) * time.Second,
		SecurityParameters: &g.UsmSecurityParameters{
			UserName:                 passBall(viper.GetString("snmpHelper.appHead")),
			AuthenticationProtocol:   g.SHA,
			AuthenticationPassphrase: passBall(viper.GetString("snmpHelper.appTrail")),
			PrivacyProtocol:          g.AES,
			PrivacyPassphrase:        passBall(viper.GetString("snmpHelper.appTrail")),
		},
	}
	snmpString = "ts_v3"

	err := params.Connect()
	if err != nil {
		m.Lock()
		defer m.Unlock()
		appendToCSV(target + ", SNMP socket not available, " + err.Error())
		return
	}
	defer params.Conn.Close()

	oids := []string{
		"1.3.6.1.2.1.1.5.0",                     //hostname
		".1.3.6.1.4.1.868.2.3.1.1.1.1.6.1",      //hostname TS
		".1.3.6.1.2.1.16.19.2.0",                //cisco version
		"1.3.6.1.4.1.868.2.80.2.1.1.1.1.2.0",    //TS model
		"1.3.6.1.4.1.868.2.80.2.1.1.1.1.2.1",    //TS model backup
		"1.3.6.1.4.1.868.2.80.2.1.1.1.1.10.0",   //TS version
		"1.3.6.1.4.1.868.2.80.2.1.1.1.1.10.1",   //TS version backup
		".1.3.6.1.4.1.5205.2.166.1.1.1.1.10.0",  //TS version backup backup idk man
		"1.3.6.1.4.1.868.2.3.1.1.1.1.10.1",      //TS version yup
		"1.3.6.1.4.1.868.2.80.2.1.1.1.1.14.0",   //TS mac address
		"1.3.6.1.4.1.868.2.80.2.1.1.1.1.14.1",   //TS mac address backup
		".1.3.6.1.4.1.5205.2.166.1.1.1.1.14.0",  //TS mac address backup backup
		".1.3.6.1.4.1.868.2.3.1.1.1.1.5.1",      //TS mac address back back back
		"1.3.6.1.4.1.868.2.80.2.1.3.1.1.1.2.1",  //TS local user
		".1.3.6.1.4.1.5205.2.166.1.3.1.1.1.2.1", //TS local user backup
	}
	result, err := params.Get(oids) // Get() accepts up to g.MAX_OIDS
	if err != nil {
		params.Version = g.Version2c
		params.Community = "blast"
		legacyResult, err := params.Get(oids)
		snmpString = "legacy_v2"
		if err != nil {
			params.Version = g.Version3
			params.SecurityParameters = &g.UsmSecurityParameters{
				UserName:                 passBall(viper.GetString("snmpHelper.appHead")),
				AuthenticationProtocol:   g.SHA,
				AuthenticationPassphrase: passBall(viper.GetString("snmpHelper.appTrail")),
				PrivacyProtocol:          g.AES256C,
				PrivacyPassphrase:        passBall(viper.GetString("snmpHelper.appTrail")),
			}
			snmpString = "cisco_v3"
			_, err := params.Get(oids)
			if err != nil {
				m.Lock()
				defer m.Unlock()
				appendToCSV(target + ", SNMP connect timed out, " + err.Error()) //converts error type to string
				return
			} else {
				//no need to return cisco results
				return
			}
		} else {
			result = legacyResult

		}

	}
	snmpOutput := target

	for _, variable := range result.Variables {
		if variable.Value != nil {
			snmpOutput += "," + string(variable.Value.([]byte))
		}
	}
	m.Lock()
	defer m.Unlock()
	appendToCSV(snmpOutput + "," + snmpString)

}

// default error checker. Built in if statement.
func CheckError(err error) {
	if err != nil {
		panic(err)
	}
}

// Used to append new lines to csv file. Default script output method. Uses os and WriteString.
func appendToCSV(nodeString string) {
	f, err := os.OpenFile("devices.csv",
		os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	CheckError(err)
	defer f.Close()

	_, err1 := f.WriteString(nodeString + "," + time.Now().Format("2006-01-02T15:04:05") + "\n")
	CheckError(err1)
}