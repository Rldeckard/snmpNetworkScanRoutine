// Copyright 2012 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.
package main

import (
	"encoding/csv"
	"fmt"
	"os"
	"sync"
	"time"

	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"

	//"github.com/Rldeckard/aesGenerate256/authGen"
	"github.com/go-ping/ping"
	g "github.com/gosnmp/gosnmp"
	"github.com/spf13/viper"
)

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

var myWindow fyne.Window
var snmpUser *widget.Entry
var snmpPriv *widget.Entry
var snmpAuth *widget.Entry
var resultsTable *fyne.Container
var content *fyne.Container


func main() {
	readCSV("devices.csv")
	

	guiApp()

}

func snmpScan(target string, community string, oids []string, snmpType string) {

	var m sync.Mutex
	//var snmpString string
	//appCode := "asdfaASDfdasaEGtei4339szv$^2faki"
	if community == "" {
		dialog.NewCustom("Oops", "Close", widget.NewLabel("Community string not detected."), myWindow).Show()
	}
	viper.AddConfigPath("configs")
	viper.SetConfigName("snmpHelper") // Register config file name (no extension)
	viper.SetConfigType("yml")        // Look for specific type
	viper.ReadInConfig()
	pinger, pingErr := ping.NewPinger(target)
	if pingErr != nil {
		m.Lock()
		defer m.Unlock()
		appendToCSV(target + ", Ping creation failed?\n")
	}
	pinger.Count = 3
	pinger.SetPrivileged(true)
	pinger.Timeout = 2000 * time.Millisecond //times out after 500 milliseconds
	pinger.Run()                                                                              // blocks until finished
	stats := pinger.Statistics()      
	rows := container.NewGridWithColumns(
		5,
		widget.NewLabel(target),
	)                                                        
	// get send/receive/rtt stats
	if stats.PacketsRecv == 0 {
		//no need to return down devices.
		return
	}
	// build our own GoSNMP struct, rather than using g.Default
	params := g.GoSNMP{
		Target:        target,
		Port:          161,
		SecurityModel: g.UserSecurityModel,
		MsgFlags:      g.AuthPriv,
		Timeout:       3 * time.Second,
	}
	if snmpType == "v3" {
		params.Version = g.Version3
		params.SecurityParameters = &g.UsmSecurityParameters{
			UserName:                 snmpUser.Text,
			AuthenticationProtocol:   g.SHA,
			AuthenticationPassphrase: snmpAuth.Text,
			PrivacyProtocol:          g.AES256C,
			PrivacyPassphrase:        snmpPriv.Text,
		}
	} else if snmpType == "v2" {
		params.Version = g.Version2c
		params.Community = community
	} else {
		params.Version = g.Version1
		params.Community = community
	}


	err := params.Connect()
	if err != nil {
		m.Lock()
		defer m.Unlock()
		appendToCSV(target + ", SNMP socket not available, " + err.Error())
		return
	}
	defer params.Conn.Close()
	
	result, err := params.Get(oids)
	
	if err != nil {
		rows.Add(widget.NewLabel("Alive, but no SNMP data"))
		m.Lock()
		resultsTable.Add(rows)
		m.Unlock()
		return
	}
	m.Lock()
	for _, variable := range result.Variables {
		if variable.Value != nil {
			switch v := variable.Value.(type) {
			case string: 
				fmt.Println(variable.Value.(string))
				rows.Add(widget.NewLabel(variable.Value.(string)))
			case []uint8:
				rows.Add(widget.NewLabel(string(v)))
			case int:
				rows.Add(widget.NewLabel(fmt.Sprint(v)))
			default: 
				fmt.Println(v)
				rows.Add(widget.NewLabel("Unhandled SNMP error "))
			}
		}
	}
	resultsTable.Add(rows)
	m.Unlock()


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
