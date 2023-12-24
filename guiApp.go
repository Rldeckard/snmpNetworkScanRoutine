package main

import (
	"fmt"
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
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

func runProgram(ipList []string, community string, snmpType string) {
	start := time.Now()
	var waitGroup sync.WaitGroup
	count := 0
	fmt.Print(snmpType)
	for _, ipGate := range ipList {
		netID := strings.Split(ipGate, ".")
		for i := 2; i <= 254; i++ {
			ipAddr := netID[0] + "." + netID[1] + "." + netID[2] + "." + strconv.Itoa(i)
			waitGroup.Add(1)
			go func() {
				defer waitGroup.Done()
				snmpScan(ipAddr, community)
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

func interactHeader(id int, label string) *fyne.Container {
	return container.NewVBox(
		container.NewHBox(
			widget.NewLabel(label),
			widget.NewButtonWithIcon("", theme.DocumentCreateIcon(), func() {
				fmt.Print(id)
			}), widget.NewButtonWithIcon("", theme.DeleteIcon(), func() {
				fmt.Print(id)
			}),
		),
	)
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
	currentValue := "v2"

	submitButton := widget.NewButton(
		"Start Scan", func() {
			if community.Text == "" {
				dialog.NewCustom("Oops", "Ok", widget.NewLabel("Community string not provided."), myWindow).Show()
				return
			} else {
				runProgram(strings.Split(deviceList.Text, ","), community.Text, snmpType)
			}
		},
	)
	submitButton.Importance = widget.HighImportance

	boxOut := canvas.NewRectangle(color.Black)
	boxOut.Resize(fyne.NewSize(150, 500))
	snmpUser := widget.NewEntry()
	snmpUser.SetPlaceHolder("SNMPv3 Username")
	snmpPriv := widget.NewPasswordEntry()
	snmpPriv.SetPlaceHolder("Priv Key")
	snmpAuth := widget.NewPasswordEntry()
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
	ipBox := container.NewBorder(
		widget.NewLabel("IP Range"),
		nil,
		nil,
		submitButton,
		deviceList,
	)

	snmpBox = container.NewBorder(
		widget.NewLabel("Community"),
		nil,
		nil,
		snmpDrop,
		community,
	)

	columns := map[string]string{
		"Device Name": "1.3.6.1.2.1.1.5.0",
		"Model":       ".1.3.6.1.4.1.868.2.3.1.1.1.1.6.1",
		"Serial":      ".1.3.6.1.2.1.16.19.2.0",
		"IP Address":  "1.3.6.1.4.1.868.2.80.2.1.1.1.1.2.0",
		"Mac Address": "1.3.6.1.4.1.868.2.80.2.1.1.1.1.2.1",
	}
	var oidForm []*widget.FormItem
	for label, entry := range columns {
		widget.NewLabel()
	}
	firstColumn := widget.NewLabel("Device Name")
	firstOID := widget.NewEntry()
	firstOID.Text = "1.3.6.1.2.1.1.5.0"
	secColumn := widget.NewLabel("Model")
	secOID := widget.NewEntry()
	secOID.Text = ".1.3.6.1.4.1.868.2.3.1.1.1.1.6.1"
	thirdColumn := widget.NewLabel("Serial")
	thirdOID := widget.NewEntry()
	thirdOID.Text = ".1.3.6.1.2.1.16.19.2.0"
	fourColumn := widget.NewLabel("IP Address")
	fourOID := widget.NewEntry()
	fourOID.Text = "1.3.6.1.4.1.868.2.80.2.1.1.1.1.2.0"
	fiveColumn := widget.NewLabel("Mac Address")
	fiveOID := widget.NewEntry()
	fiveOID.Text = "1.3.6.1.4.1.868.2.80.2.1.1.1.1.2.1"
	oidForm := []*widget.FormItem{
		{Text: firstColumn.Text, Widget: firstOID},
		{Text: secColumn.Text, Widget: secOID},
		{Text: thirdColumn.Text, Widget: thirdOID},
		{Text: fourColumn.Text, Widget: fourOID},
		{Text: fiveColumn.Text, Widget: fiveOID},
	}

	editButton := widget.NewButton("Edit Columns", func() {
		dialog := dialog.NewForm("Edit", "Update", "Cancel", oidForm, func(ok bool) {
			fmt.Print("Update OIDs")
		}, myWindow)
		dialog.Resize(fyne.NewSize(600, 0))
		dialog.Show()
	})
	top = container.NewVBox(
		ipBox,
		snmpBox,
		editButton,
	)
	resultsTable := container.NewGridWithColumns(
		5,
		firstColumn, secColumn, thirdColumn, fourColumn, fiveColumn,
	)

	content := container.NewBorder(
		top,
		nil,
		nil,
		nil,
		resultsTable,
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
