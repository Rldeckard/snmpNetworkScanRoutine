package main

import (
	"image/color"
	"log"
	"strconv"
	"strings"
	"sync"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"
)

func runProgram(ipList []string, oids []string, community string, snmpType string) {
	start := time.Now()
	var waitGroup sync.WaitGroup
	count := 0
	for _, ipGate := range ipList {
		netID := strings.Split(ipGate, ".")
		for i := 1; i <= 254; i++ {
			ipAddr := netID[0] + "." + netID[1] + "." + netID[2] + "." + strconv.Itoa(i)
			waitGroup.Add(1)
			go func() {
				defer waitGroup.Done()
				snmpScan(ipAddr, community, oids, snmpType)
			}()
			if count > 200 { //only allows 200 routines at once. TODO: Needs replaced with real logic at some point to manage snmp connections.
				time.Sleep(time.Duration(500 * time.Millisecond))
				count = 0
			}
			count++
		}
	}
	waitGroup.Wait()
	duration := time.Since(start)
	log.Print(duration)
}

type Columns struct {
	colname string
	oid widget.Entry
}

func guiApp() {

	myApp := app.New()
	myWindow = myApp.NewWindow("SNMP Scanner")
	myWindow.Resize(fyne.NewSize(950, 500))

	// Main menu

	fileMenu := fyne.NewMenu("File",
		fyne.NewMenuItem("Quit", func() { myApp.Quit() }),
	)
	helpMenu := fyne.NewMenu("Help",
		fyne.NewMenuItem("About", func() {
			dialog.ShowCustom("About", "Close", container.NewVBox(
				widget.NewLabel("Welcome to SNMP Scanner for Windows."),
				widget.NewLabel("Version: v0.0.1"),
				widget.NewLabel("Author: Ryan Deckard"),
			), myWindow)
		}))

	mainMenu := fyne.NewMainMenu(
		fileMenu,
		helpMenu,
	)
	myWindow.SetMainMenu(mainMenu)
	outTitle := widget.NewLabel("Switch Output")
	outTitle.TextStyle.Bold = true
	outTitle.Alignment = fyne.TextAlignCenter

	progBar := widget.NewProgressBar()
	progBar.Hide()

	deviceList := widget.NewEntry()
	community := widget.NewEntry()
	var snmpType string
	var snmpBox *fyne.Container
	var top *fyne.Container
	var columns []Columns
	var headerRow *fyne.Container
	currentValue := "v2"


	boxOut := canvas.NewRectangle(color.Black)
	boxOut.Resize(fyne.NewSize(150, 500))
	snmpUser = widget.NewEntry()
	snmpUser.SetPlaceHolder("SNMPv3 Username")
	snmpPriv = widget.NewPasswordEntry()
	snmpPriv.SetPlaceHolder("Priv Key")
	snmpAuth = widget.NewPasswordEntry()
	snmpAuth.SetPlaceHolder("Auth Key")

	snmpDrop := widget.NewSelect([]string{"v1", "v2", "v3"}, func(value string) {
		snmpType = value
	})
	snmpDrop.SetSelectedIndex(1)
	snmpFields := container.NewBorder(
		widget.NewLabel("Community"),
		nil,
		nil,
		snmpDrop,
		container.NewGridWithColumns(
			3,
			snmpUser,
			snmpPriv,
			snmpAuth,
		),
	)
	snmpDrop.OnChanged = func(value string) {
		if currentValue == value {
			return
		}
		if value == "v3" {
			top.Remove(snmpBox)
			top.Add(snmpFields)
		}
		if (value == "v2" && currentValue != "v1") || (value == "v1" && currentValue != "v2") {
			top.Add(snmpBox)
			top.Remove(snmpFields)
		}
		currentValue = value
	}
	

	snmpBox = container.NewBorder(
		widget.NewLabel("Community"),
		nil,
		nil,
		snmpDrop,
		community,
	)
	
	columns = []Columns{
		{"Device Name",widget.Entry{Text: "1.3.6.1.2.1.1.5.0"}},
		{"IP Address",  widget.Entry{Text: "1.3.6.1.4.1.868.2.80.2.1.1.1.1.2.0"}},
		{"Model",       widget.Entry{Text: "1.3.6.1.2.1.43.11.1.1.8.1.1"}},
		{"Serial",     widget.Entry{Text: ".1.3.6.1.2.1.16.19.2.0"}},
		{"Mac Address", widget.Entry{Text: "1.3.6.1.4.1.868.2.80.2.1.1.1.1.2.1"}},
	}

	resultsTable = container.NewVBox()
	headerRow = container.NewGridWithColumns(5) 
	for i:=0;i<len(columns);i++ {
		headerRow.Add(widget.NewLabel(columns[i].colname))
	}
	outputScroll := container.NewVScroll(resultsTable)
	outputScroll.SetMinSize(fyne.NewSize(450, 0))

	/*
	editButton := widget.NewButton("Edit Probes", func() {
		var oidForm []*widget.FormItem
		for label, entry := range columns {
			oidForm = append(oidForm, widget.NewFormItem(label, entry))
		}
		dialog := dialog.NewForm("Edit", "Update", "Cancel", oidForm, func(ok bool) {
			//nothing to do. OIDs are updated automatically. TODO: figure out how to handle cancel.
		}, myWindow)
		dialog.Resize(fyne.NewSize(600, 0))
		dialog.Show()
	})*/
	
	submitButton := widget.NewButton(
		"Start Scan", func() {
			resultsTable.RemoveAll()
			resultsTable.Add(headerRow)
			if community.Text == "" {
				dialog.NewCustom("Oops", "Ok", widget.NewLabel("Community string not provided."), myWindow).Show()
				return
			} else {
				var oids []string
				for i:=0;i<len(columns);i++ {
					oids = append(oids, columns[i].oid.Text)
				}
				runProgram(strings.Split(deviceList.Text, ","), oids, community.Text, snmpType)
			}



		},
	)
	submitButton.Importance = widget.HighImportance
	ipBox := container.NewBorder(
		widget.NewLabel("IP Range"),
		nil,
		nil,
		submitButton,
		deviceList,
	)
	top = container.NewVBox(
		ipBox,
		snmpBox,
	)
	content = container.NewBorder(
		top,
		nil,
		nil,
		nil,
		outputScroll,
	)

	// Display our content
	myWindow.SetContent(content)
	// Close the App when Escape key is pressed
	myWindow.Canvas().SetOnTypedKey(func(keyEvent *fyne.KeyEvent) {

		if keyEvent.Name == fyne.KeyEscape {
			myApp.Quit()
		}
	})

	// Show window and run app
	myWindow.ShowAndRun()
}
