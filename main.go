package main

import (
    "github.com/gotk3/gotk3/gtk"
    "github.com/gotk3/gotk3/glib"
    "log"
    "os"
    "time"
    "sync"
    "io"
    "io/ioutil"
    "strconv"
    "strings"
    "encoding/json"
    "./EgregoreSocket"
)

type answer struct {
  Status bool
  Error error
}

type settings struct {
  RSAKeyLength  string `json:"rsa_key_length"`
  Port          string `json:"port"`
}

func Settings() *settings {
  obj := new(settings)
  return obj
}

type EgregoreGui struct {
  window  *gtk.Window

  conInfoBar *gtk.Entry

  messageBar *gtk.TextView
  senderBar *gtk.TextView

  sendButton *gtk.Button
  tryConButton *gtk.Button
  waitConButton *gtk.ToggleButton
  closeConButton *gtk.Button

  socket *EgregoreSocket.EgregoreSocket

  settings *settings

  //support variable, it is ugly, but work
  answer *answer
  wg *sync.WaitGroup
}


func New() *EgregoreGui {
  obj := new(EgregoreGui)
  return obj
}

//setters and getters

func (self *EgregoreGui) SetWindow(w *gtk.Window) {
  self.window = w
}

func (self *EgregoreGui) Window() *gtk.Window {
  return self.window
}

func (self *EgregoreGui) SetConInfoBar(w *gtk.Entry) {
  self.conInfoBar = w
}

func (self *EgregoreGui) ConInfoBar() *gtk.Entry {
  return self.conInfoBar
}

func (self *EgregoreGui) SetMessageBar(w *gtk.TextView) {
  self.messageBar = w
}

func (self *EgregoreGui) MessageBar() *gtk.TextView {
  return self.messageBar
}

func (self *EgregoreGui) SetSenderBar(w *gtk.TextView) {
  self.senderBar = w
}

func (self *EgregoreGui) SenderBar() *gtk.TextView {
  return self.senderBar
}

func (self *EgregoreGui) SetSendButton(w *gtk.Button) {
  self.sendButton = w
}

func (self *EgregoreGui) SendButton() *gtk.Button {
  return self.sendButton
}

func (self *EgregoreGui) SetTryConButton(w *gtk.Button) {
  self.tryConButton = w
}

func (self *EgregoreGui) TryConButton() *gtk.Button {
  return self.tryConButton
}

func (self *EgregoreGui) SetWaitConButton(w *gtk.ToggleButton) {
  self.waitConButton = w
}

func (self *EgregoreGui) WaitConButton() *gtk.ToggleButton {
  return self.waitConButton
}

func (self *EgregoreGui) SetCloseConButton(w *gtk.Button) {
  self.closeConButton = w
}

func (self *EgregoreGui) CloseConButton() *gtk.Button {
  return self.closeConButton
}

func (self *EgregoreGui) SetSocket(s *EgregoreSocket.EgregoreSocket) {
  self.socket = s
}

func (self *EgregoreGui) Socket() *EgregoreSocket.EgregoreSocket {
  return self.socket
}

func (self *EgregoreGui) SetSettings(s *settings) {
  self.settings = s
}

func (self *EgregoreGui) Settings() *settings {
  return self.settings
}

func (self *EgregoreGui) SetAnswer(a *answer) {
  self.answer = a
}

func (self *EgregoreGui) Answer() *answer {
  return self.answer
}

func (self *EgregoreGui) SetWaitGroup(wg *sync.WaitGroup) {
  self.wg = wg
}

func (self *EgregoreGui) WaitGroup() *sync.WaitGroup {
  return self.wg
}

//init elements
func (self *EgregoreGui) initElements() {
  b, err := gtk.BuilderNew()
  if err != nil {
       log.Fatal("Error:", err)
   }
   err = b.AddFromFile("Egregore-gtk.glade")
   if err != nil {
       log.Fatal("Error:", err)
   }

   obj, err := b.GetObject("mainWindow")
   if err != nil {
       log.Fatal("Error:", err)
   }
   self.window = obj.(*gtk.Window)


   obj, err = b.GetObject("conInfoBar")
   if err != nil {
     log.Fatal("Error", err)
   }
   self.conInfoBar = obj.(*gtk.Entry)

   obj, err = b.GetObject("messageBar")
   if err != nil {
     log.Fatal("Error", err)
   }
   self.messageBar = obj.(*gtk.TextView)

   obj, err = b.GetObject("senderBar")
   if err != nil {
     log.Fatal("Error", err)
   }
   self.senderBar = obj.(*gtk.TextView)


   obj, err = b.GetObject("sendButton")
   if err != nil {
     log.Fatal("Error", err)
   }
   self.sendButton = obj.(*gtk.Button)

   obj, err = b.GetObject("tryConButton")
   if err != nil {
     log.Fatal("Error", err)
   }
   self.tryConButton = obj.(*gtk.Button)

   obj, err = b.GetObject("waitConButton")
   if err != nil {
     log.Fatal("Error", err)
   }
   self.waitConButton = obj.(*gtk.ToggleButton)

   obj, err = b.GetObject("closeConButton")
   if err != nil {
     log.Fatal("Error", err)
   }
   self.closeConButton = obj.(*gtk.Button)

   //init socket object

   self.socket = EgregoreSocket.New()
   self.socket.SetLogFunc(self.addSystemMessage)
   self.socket.SetDecisionFunc(self.decisionFunc)
   self.answer = new(answer)
}

//bind events
func (self *EgregoreGui) bindEvents() {
  self.window.Connect("destroy", func() {
     gtk.MainQuit()
  })

  self.window.Connect("delete-event", func() bool {
    return self.OnClose()
  })

  self.sendButton.Connect("clicked", func()  {
    self.OnSendButtonClick()
  })

  self.tryConButton.Connect("clicked", func() {
    self.OnTryConButtonClick()
  })

  self.waitConButton.Connect("toggled", func() {
    mode := self.waitConButton.GetMode()
    if mode {
      self.OnWaitConOff()
    } else {
      self.OnWaitConOn()
    }
    self.waitConButton.SetMode(!mode)
  })

  self.closeConButton.Connect("clicked", func() {
    self.OnCloseConButtonClick()
  })

}

//init interface

func (self *EgregoreGui) Init() {
  gtk.Init(&os.Args)
  self.initElements()
  self.bindEvents()
  self.InitState()
  self.window.ShowAll()
  go self.BackgroundActivity()
  gtk.Main()
}

//button events

func (self *EgregoreGui) OnSendButtonClick() {
  if self.socket.Ready() {
    msg := self.getMessage()
    if msg != "" {
      err := self.socket.Send([]byte(msg))
      if err == nil {
        self.addUserMessage(msg)
        self.clearMessage()
      } else {
        self.addSystemMessage("Send message error: " + err.Error())
      }
    } else {
      self.addSystemMessage("You can not send empty message")
    }
  } else {
    self.addSystemMessage("Socket connection is not ready yet")
  }
}

func (self *EgregoreGui) readParamsFromFile(path string) error {
  file, err := ioutil.ReadFile(path)
  if err != nil {
    self.addSystemMessage("Reading settings file error: " + err.Error() + ".")
    return err
  }
  self.settings =  Settings()
  err = json.Unmarshal([]byte(file), self.settings)
  if err != nil {
    self.addSystemMessage("Reading settings file error: " + err.Error() + ".")
    return err
  }
  return nil
}

func (self *EgregoreGui) setParamsFromSettingsStruct() error {
  var err error
  port, err := strconv.Atoi(self.settings.Port)
  if err != nil {
    self.addSystemMessage("Error: Check port param in settings file. Fix it and try again.")
    return err
  }
  self.socket.SetPort(port)
  length, err := strconv.Atoi(self.settings.RSAKeyLength)
  if err != nil {
    self.addSystemMessage("Error: Check key length param in settings file. Fix it and try again.")
    return err
  }
  self.socket.SetRSAKeyLength(length)
  return nil
}

func (self *EgregoreGui) initSettings() error {
  var err error
  err = self.readParamsFromFile("settings.json")
  if err != nil {
    return err
  }
  err = self.setParamsFromSettingsStruct()
  if err != nil {
    return err
  }
  return nil
}

func (self *EgregoreGui) OnTryConButtonClick() {
  log.Print("Try to connect button click")
  var err error
  err = self.initSettings()
  if err != nil {
    return
  }
  self.socket.SetRemoteAddr(self.getRemoteAddr())
  go self.FullyTryToCon()
}

func (self *EgregoreGui) OnWaitConOn() {
  log.Print("Wait for connection: On")
  self.tryConButton.SetSensitive(false)
  var err error
  err = self.initSettings()
  if err != nil {
    return
  }
  go self.FullyWaitForCon()
}

func (self *EgregoreGui) OnWaitConOff() {
  log.Print("Wait for connection: Off")
  if !self.socket.AlreadyCon() {
      self.tryConButton.SetSensitive(true)
  }
  self.socket.SetWaitForCon(false)
}

func (self *EgregoreGui) OnCloseConButtonClick() {
  log.Print("Close connection button click")
  md := gtk.MessageDialogNew(
            self.window,
            gtk.DIALOG_MODAL,
            gtk.MESSAGE_QUESTION,
            gtk.BUTTONS_YES_NO,
            "Do you want close this connection right now?")
  if md.Run() == gtk.RESPONSE_YES {
    if self.socket.AlreadyCon() {
        self.OnCloseConnection()
    }
  }
  md.Destroy()
}

func (self *EgregoreGui) OnClose() bool {
  md := gtk.MessageDialogNew(
            self.window,
            gtk.DIALOG_MODAL,
            gtk.MESSAGE_QUESTION,
            gtk.BUTTONS_YES_NO,
            "Do you want quit from this program right now?")
    if md.Run() == gtk.RESPONSE_YES {
      gtk.MainQuit()
    }
    md.Destroy()
    return true
}

func (self *EgregoreGui) OnAcceptConnection() {
  self.InitState()
  self.socket.SetReady(true)
}

func (self *EgregoreGui) OnCloseConnection() {
  self.socket.Close()
  self.socket = EgregoreSocket.New()
  self.InitState()
}

func (self *EgregoreGui) BackgroundActivity() {
  var msg []byte
  var err error
  for {
    if self.socket.Ready() {
      msg, err = self.socket.Recv()
      if err == nil {
        if msg != nil {
          self.addRecieverMessage(string(msg))
        }
      } else {
        if strings.Contains(err.Error(), "timeout") {
          continue
        } else if err == io.EOF {
          if self.socket.AlreadyCon() {
              self.OnCloseConnection()
          }
        } else {
          self.addSystemMessage(err.Error())
        }
      }
    }
    time.Sleep(time.Second)
  }
}

//initial state

func (self *EgregoreGui) InitState() {
  if self.socket.AlreadyCon() {
    self.setConInfoBarText(self.socket.RemoteAddr())
    self.tryConButton.SetSensitive(false)
    self.waitConButton.SetProperty("active", false)
    self.waitConButton.SetSensitive(false)

    self.sendButton.SetSensitive(true)
    self.closeConButton.SetSensitive(true)
  } else {
    self.conInfoBar.SetProperty("editable", true)

    self.tryConButton.SetSensitive(true)
    self.waitConButton.SetSensitive(true)

    self.sendButton.SetSensitive(false)
    self.closeConButton.SetSensitive(false)
  }
}

//logic

func (self *EgregoreGui) decisionFunc() (bool, error) {
  self.wg = new(sync.WaitGroup)
  self.wg.Add(1)
  glib.IdleAdd(self.unsafeDecisionFunc, nil)
  self.wg.Wait()
  return self.answer.Status, self.answer.Error
}

func (self *EgregoreGui) unsafeDecisionFunc() {
  md := gtk.MessageDialogNew(
            self.window,
            gtk.DIALOG_MODAL,
            gtk.MESSAGE_QUESTION,
            gtk.BUTTONS_YES_NO,
            "Do you want accept a connection from (" + self.socket.RemoteAddr() + ")?")
    if md.Run() == gtk.RESPONSE_YES {
      self.answer.Status = true
    } else {
      self.answer.Status = false
    }
    self.answer.Error = nil
    md.Destroy()
    self.wg.Done()
}

func (self *EgregoreGui) unsafeAddMessage(arg [3]string) {
  self.messageBar.SetProperty("editable", true)
  buffer, _ := self.messageBar.GetBuffer()
  buffer.InsertWithTagByName(buffer.GetEndIter(), arg[0] + ": ", arg[2])
  buffer.Insert(buffer.GetEndIter(), arg[1] + "\n")
  self.messageBar.SetProperty("editable", false)
}

func (self *EgregoreGui) addMessage(prefix string, msg string, tagname string) {
  glib.IdleAdd(self.unsafeAddMessage, [3]string{prefix, msg, tagname})
}

func (self *EgregoreGui) addUserMessage(msg string) {
  self.addMessage("You", msg, "usr_msg")
}

func (self *EgregoreGui) addRecieverMessage(msg string) {
  self.addMessage("(" + self.socket.RemoteAddr() + ")", msg, "rcv_msg")
}

func (self *EgregoreGui) addSystemMessage(msg string) {
  self.addMessage("System", msg, "sys_msg")
}

func (self *EgregoreGui) setConInfoBarText(text string) {
  self.conInfoBar.SetProperty("editable", true)
  self.conInfoBar.SetText(text)
  self.conInfoBar.SetProperty("editable", false)
}

func (self *EgregoreGui) getRemoteAddr() string {
  result, _ := self.conInfoBar.GetText()
  return result
}

func (self *EgregoreGui) getMessage() string {
  buffer, _ := self.senderBar.GetBuffer()
  text, _ := buffer.GetText(buffer.GetStartIter(), buffer.GetEndIter(), true)
  return text
}

func (self *EgregoreGui) clearMessage() {
  glib.IdleAdd(self.clearMessage, nil)
}

func (self *EgregoreGui) unsafeClearMessage() {
  buffer, _ := self.senderBar.GetBuffer()
  buffer.SetText("")
}

func (self *EgregoreGui) FullyWaitForCon() {
  var status bool
  var err error
  for {
    status, err = self.socket.WaitConnect()
    if err != nil {
      self.addSystemMessage(err.Error())
      self.socket.Refresh()
      break
    } else if !status {
      self.addSystemMessage("You rejected the connection")
      self.socket.Refresh()
      continue
    } else {
      self.addSystemMessage("You accepted the connection")
      self.OnAcceptConnection()
      break
    }
  }
}

func (self *EgregoreGui) FullyTryToCon() {
  status, err := self.socket.Connect()
  if err != nil {
    self.addSystemMessage(err.Error())
    self.socket.Refresh()
  } else if !status {
    self.addSystemMessage("Connection was rejected")
    self.socket.Refresh()
  } else {
    self.addSystemMessage("Connection was accepted")
    self.OnAcceptConnection()
  }
}

func main() {
  gui := New();
  gui.Init()
}
