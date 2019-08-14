package EgregoreSocket

import (
    "crypto/rand"
    "crypto/sha512"
    "crypto/cipher"
    "crypto/aes"
    "crypto/rsa"
    "crypto/x509"
    "golang.org/x/crypto/blowfish"
    "unix"
    "net"
    "log"
    "errors"
    "time"
    "syscall"
    "strconv"
    "strings"
    "encoding/binary"
    "golang.org/x/sys/unix"
)

const (
  YES byte = 73
  NO  byte = 72
  END byte = 67
  MAX_MSG_LEN uint32 = 4294967295 //2^32 - 1
  ANSWER string = "Egregore_client_is_here"
  DEFAULT_PORT int = 8196
  DEFAULT_RSA_KEY_PAIR_LENGTH int = 4096
  DEFAULT_READ_MESSAGE_BLOCK_DURATION time.Duration = 3 * time.Second
)

type EgregoreSocket struct {
  socket *net.TCPConn

  port int

  remoteAddr string

  rsaKeyPair []*rsa.PrivateKey
  rsaKeyLength int

  aesKey []byte
  blowfishKey []byte

  remoteRSAKey []*rsa.PublicKey
  remoteAESKey []byte
  remoteBlowfishKey []byte

  iAmHost bool
  waitForCon bool
  alreadyCon bool
  ready bool

  messageBlockReadingTimeout time.Duration

  logFunc func(string)
  decisionFunc func() (bool, error)
}

//constructor

func New() *EgregoreSocket {
    obj := new(EgregoreSocket)
    obj.rsaKeyPair = make([]*rsa.PrivateKey, 2)
    obj.remoteRSAKey = make([]*rsa.PublicKey, 2)
    obj.ready = false
    obj.messageBlockReadingTimeout = DEFAULT_READ_MESSAGE_BLOCK_DURATION
    obj.port = DEFAULT_PORT
    obj.rsaKeyLength = DEFAULT_RSA_KEY_PAIR_LENGTH
    return obj
}

//setters and getters

func (self *EgregoreSocket) SetSocket(socket *net.TCPConn) {
  self.socket = socket
}

func (self *EgregoreSocket) Socket() *net.TCPConn {
  return self.socket
}

func (self *EgregoreSocket) SetPort(port int) {
  if port >= 0 {
    self.port = port
  } else {
    self.port = DEFAULT_PORT
    self.Log("Setting param error: port number must be natural number. Auto set default port number (" + strconv.Itoa(DEFAULT_PORT) + ").")
  }
}

func (self *EgregoreSocket) Port() int {
  return self.port
}

func (self *EgregoreSocket) SetRemoteAddr(addr string) {
  self.remoteAddr = addr
}

func (self *EgregoreSocket) RemoteAddr() string {
  return self.remoteAddr
}

func (self *EgregoreSocket) SetRSAKeyPair(keyPair []*rsa.PrivateKey) {
  self.rsaKeyPair = keyPair
}

func (self *EgregoreSocket) RSAKeyPair() []*rsa.PrivateKey {
  return self.rsaKeyPair
}

func (self *EgregoreSocket) SetRSAKeyLength(len int) {
  if len >= DEFAULT_RSA_KEY_PAIR_LENGTH && (len & (len - 1) == 0) {
    self.rsaKeyLength = len
  } else {
    self.rsaKeyLength = DEFAULT_RSA_KEY_PAIR_LENGTH
    self.Log("Setting param error: rsa key pair length must be >= 4096 and be power of 2 (2^n). Auto set default key length (" + strconv.Itoa(DEFAULT_RSA_KEY_PAIR_LENGTH) + ").")
  }
}

func (self *EgregoreSocket) RSAKeyLength() int {
  return self.rsaKeyLength
}

func (self *EgregoreSocket) SetAESKey(bytes []byte) {
  copy(self.aesKey, bytes)
}

func (self *EgregoreSocket) AESKey() []byte {
  return self.aesKey
}

func (self *EgregoreSocket) SetBlowfishKey(bytes []byte) {
  copy(self.blowfishKey, bytes)
}

func (self *EgregoreSocket) BlowfishKey() []byte {
  return self.blowfishKey
}

func (self *EgregoreSocket) SetRemoteRSAKey(publicKey []*rsa.PublicKey) {
  self.remoteRSAKey = publicKey
}

func (self *EgregoreSocket) RemotePublicRSAKey() []*rsa.PublicKey {
  return self.remoteRSAKey
}

func (self *EgregoreSocket) SetRemoteAESKey(bytes []byte) {
  self.remoteAESKey = make([]byte, len(bytes))
  copy(self.remoteAESKey, bytes)
}

func (self *EgregoreSocket) RemoteAESKey() []byte {
  return self.remoteAESKey
}

func (self *EgregoreSocket) SetRemoteBlowfishKey(bytes []byte) {
  self.remoteBlowfishKey = make([]byte, len(bytes))
  copy(self.remoteBlowfishKey, bytes)
}

func (self *EgregoreSocket) RemoteBlowfishKey() []byte {
  return self.remoteBlowfishKey
}

func (self *EgregoreSocket) SetIAmHost(b bool) {
  self.iAmHost = b
}

func (self *EgregoreSocket) IAmHost() bool {
  return self.iAmHost
}

func (self *EgregoreSocket) SetWaitForCon(b bool) {
  self.waitForCon = b
}

func (self *EgregoreSocket) WaitForCon() bool {
  return self.waitForCon
}

func (self *EgregoreSocket) SetAlreadyCon(b bool) {
  self.alreadyCon = b
}

func (self *EgregoreSocket) AlreadyCon() bool {
  return self.alreadyCon
}

func (self *EgregoreSocket) SetReady(b bool) {
  self.ready = b
}

func (self *EgregoreSocket) Ready() bool {
  return self.ready
}

func (self *EgregoreSocket) SetMessageBlockReadingTimeout(d time.Duration) {
  self.messageBlockReadingTimeout = d
}

func (self *EgregoreSocket) MessageBlockReadingTimeout() time.Duration {
  return self.messageBlockReadingTimeout
}

func (self *EgregoreSocket) SetLogFunc(f func(string)) {
  self.logFunc = f
}

func (self *EgregoreSocket) LogFunc() func(string) {
  return self.logFunc
}

func (self *EgregoreSocket) SetDecisionFunc(f func() (bool, error)) {
  self.decisionFunc = f
}

func (self *EgregoreSocket) DecisionFunc() func() (bool, error) {
  return self.decisionFunc
}

//socket operation

func (self *EgregoreSocket) Connect() (bool, error) {
  var err error
  var status bool
  self.Log("Connection to (" + self.remoteAddr + ") from port " + strconv.Itoa(self.port) + " was started. Please wait...")
  err = self.lowConnect()
  if err != nil {
    return false, err
  }
  status, err = self.recieverHandshake()
  if err != nil {
    return false, err
  } else if !status {
    return false, nil
  }
  err = self.keyGeneration()
  if err != nil {
    return false, err
  }
  err = self.keyExchange()
  if err != nil {
    return false, err
  }
  self.ready = true
  self.Log("Now your connected to (" + self.remoteAddr + ").")
  return true, nil
}

func (self *EgregoreSocket) WaitConnect() (bool, error) {
  self.Log("Wait for new connection. Please wait...")
  var err error
  var status bool
  err = self.lowWaitConnect()
  if err != nil {
    return false, err
  }
  status, err = self.hostHandshake()
  if err != nil {
    return false, err
  } else if !status {
    return false, nil
  }
  status, err = self.decision()
  if err != nil {
    self.Log("Low level error: " + err.Error() + ".")
    return false, err
  }
  err = self.hostDecision(status)
  if err != nil {
    return false, err
  }
  if status {
    err = self.keyGeneration()
    if err != nil {
      return false, err
    }
    err = self.keyExchange()
    if err != nil {
      return false, err
    }
    self.ready = true
    self.Log("Now your connected to (" + self.remoteAddr + ").")
    return true, nil
  } else {
    return false, nil
  }
}

func (self *EgregoreSocket) lowConnect() error {
  var err error
  self.Log("Low level connection to (" + self.remoteAddr + ") from port " + strconv.Itoa(self.port) + " was started. Please wait...")
  addr, err := net.ResolveTCPAddr("tcp", self.remoteAddr)
  if err != nil {
    self.Log("Connection error: " + err.Error() + ".")
    return err
  }
  laddr, err := net.ResolveTCPAddr("tcp", ":" + strconv.Itoa(self.port))
  if err != nil {
    self.Log("Connection error: " + err.Error() + ".")
    return err
  }
  conn, err := net.DialTCP("tcp", laddr, addr)
  if err != nil {
    self.Log("Connection error: " + err.Error() + ".")
    return err
  }
  self.setFieldsOnConEvent(conn, false)
  rawConn, err := self.socket.SyscallConn()
  if err != nil {
    self.Log("Connection error: " + err.Error() + ".")
    return err
  }
  err = rawConn.Control(self.setReuse)
  if err != nil {
    self.Log("Connection error: " + err.Error() + ".")
    return err
  }
  self.Log("Low level connection to (" + self.remoteAddr + ") from port " + strconv.Itoa(self.port) + " was successfully completed.")
  return nil
}

func (self *EgregoreSocket) lowWaitConnect() error {
  self.Log("Waiting for connection to port " + strconv.Itoa(self.port) + " was started. Please wait...")
  self.waitForCon = true
  addr, err := net.ResolveTCPAddr("tcp", ":" + strconv.Itoa(self.port))
  if err != nil {
    self.waitForCon = false
    self.Log("Connection error: " + err.Error() + ".")
    return err
  }
  listener, err := net.ListenTCP("tcp", addr)
  if err != nil {
    self.waitForCon = false
    self.Log("Connection error: " + err.Error() + ".")
    return err
  }
  rawConn, err := listener.SyscallConn()
  if err != nil {
    self.waitForCon = false
    self.Log("Connection error: " + err.Error() + ".")
    return err
  }
  err = rawConn.Control(self.setReuse)
  if err != nil {
    self.waitForCon = false
    self.Log("Connection error: " + err.Error() + ".")
    return err
  }
  go func() {
    for {
      if !self.waitForCon {
          listener.Close()
          return
        }
    }
  }()
  conn, err := listener.AcceptTCP()
  if err != nil {
    self.waitForCon = false
    self.Log("Connection error: " + err.Error() + ".")
    return err
  }
  listener.Close()
  self.remoteAddr = conn.RemoteAddr().String()
  self.setFieldsOnConEvent(conn, true)
  rawConn, err = self.socket.SyscallConn()
  if err != nil {
    self.waitForCon = false
    self.Log("Connection error: " + err.Error() + ".")
    return err
  }
  err = rawConn.Control(self.setReuse)
  if err != nil {
    self.waitForCon = false
    self.Log("Connection error: " + err.Error() + ".")
    return err
  }
  self.Log("Low level connection to (" + self.remoteAddr + ") from port " + strconv.Itoa(self.port) + " was successfully completed.")
  return nil
}

func (self *EgregoreSocket) sendMessage(msg []byte) error {
  bytes := make([]byte, len(msg))
  copy(bytes, msg)
  var sendBytes []byte
  var err error
  n := len(bytes)
  temp := self.convertUint32ToBytes(MAX_MSG_LEN)
  boundary := int(MAX_MSG_LEN)
  for n > 0 {
    if n > boundary {
      sendBytes = append(append(temp, NO), bytes[:boundary]...)
      bytes = bytes[boundary:]
      n -= boundary
    } else if n == boundary {
      sendBytes = append(append(temp, YES), bytes[:boundary]...)
      n = 0
    } else {
      rest := self.convertUint32ToBytes(uint32(n))
      sendBytes = append(append(rest, YES), bytes[:n]...)
      n = 0
    }
    _, err = self.socket.Write(sendBytes)
    if err != nil {
      return err
    }
  }
  return nil
}

func (self *EgregoreSocket) recvMessage() ([]byte, error) {
  var bytes []byte
  buf := make([]byte, 1024)
  var n uint32 = 0
  var signal byte = NO
  for signal != YES {
    if self.ready {
      self.socket.SetReadDeadline(time.Now().Add(self.messageBlockReadingTimeout))
    } else {
      self.socket.SetReadDeadline(time.Time{})
    }
    k, err := self.socket.Read(buf)
    if err == nil {
      if n == 0 {
        n, signal = self.getMetaMesssageInfo(buf)
        bytes = append(bytes, buf[5:k]...)
        n -= uint32(k - 5)
      } else {
        bytes = append(bytes, buf[:k]...)
        n -= uint32(k)
      }
    } else {
      return nil, err
    }
  }
  return bytes, nil
}

func (self *EgregoreSocket) Send(msg []byte) error {
  var err error
  iv, err := self.genIV()
  if err != nil {
    self.Log("Error sending message: " + err.Error() + ".")
    return err
  }
  bytes, err := self.encodeMessage(msg)
  if err != nil {
    self.Log("Error sending message: " + err.Error() + ".")
    return err
  }
  bytes, err = self.encryptAESMessage(bytes, iv)
  if err != nil {
    self.Log("Error sending message: " + err.Error() + ".")
    return err
  }
  bytes, err = self.encryptBlowfishMessage(bytes, iv[:8])
  if err != nil {
    return err
  }
  bytes = append(iv, bytes...)
  err = self.sendMessage(bytes)
  if err != nil {
    self.Log("Error sending message: " + err.Error() + ".")
    return err
  }
  return nil
}

func (self *EgregoreSocket) Recv() ([]byte, error) {
  var bytes []byte
  var err error
  bytes, err = self.recvMessage()
  if err != nil {
    if !strings.Contains(err.Error(), "timeout") {
      self.Log("Error receiving message: " + err.Error() + ".")
    }
    return nil, err
  }
  iv := make([]byte, 16)
  copy(iv, bytes[:16])
  bytes = bytes[16:]
  bytes, err = self.decryptBlowfishMessage(bytes, iv[:8])
  if err != nil {
    self.Log("Error receiving message: " + err.Error() + ".")
    return nil, err
  }
  bytes, err = self.decryptAESMessage(bytes, iv)
  if err != nil {
    self.Log("Error receiving message: " + err.Error() + ".")
    return nil, err
  }
  bytes, err = self.decodeMessage(bytes)
  if err != nil {
    self.Log("Error receiving message: " + err.Error() + ".")
    return nil, err
  }
  return bytes, nil
}

func (self *EgregoreSocket) setReuse(fd uintptr) {
  syscall.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
}

func (self *EgregoreSocket) Close() {
  if self.socket != nil {
    self.alreadyCon = false
    self.waitForCon = false
    self.iAmHost = false
    self.ready = false
    rawConn, _ := self.socket.SyscallConn()
    rawConn.Control(self.setReuse)
    self.socket.CloseRead()
    self.socket.CloseWrite()
    self.socket.Close()
    self.socket = nil
    self.Log("Connection was successfully closed.")
  }
}

func (self *EgregoreSocket) Refresh() {
  self.Close()
}

//key generation

func (self *EgregoreSocket) keyGeneration() error {
  self.Log("Key generation was started. Please wait...")
  self.Log("RSA key pair generation was started. Please wait...")
  err := self.genRSAPair()
  if (err != nil) {
    self.Log("RSA key pair generation was failed. " + err.Error() + ".")
    return err
  }
  self.Log("RSA key pair generation was successfully completed.")
  self.Log("AES key generation was started. Please wait...")
  err = self.genAES()
  if (err != nil) {
    self.Log("AES key generation was failed. " + err.Error() + ".")
    return err
  }
  self.Log("AES key generation was successfully completed.")
  self.Log("Blowfish key generation was started. Please wait...")
  err = self.genBlowfish()
  if (err != nil) {
    self.Log("Blowfish key generation was failed. " + err.Error() + ".")
    return err
  }
  self.Log("Blowfish key generation was successfully completed.")
  self.Log("Key generation was successfully completed.")
  return nil
}

//rsa generation

func (self *EgregoreSocket) genRSAPair() error {
  var key *rsa.PrivateKey = nil
  var err error
  i := 0
  for i < 2 {
    key, err = rsa.GenerateKey(rand.Reader, self.rsaKeyLength)
    if err != nil {
      return err
    }
    self.rsaKeyPair[i] = key
    i += 1
  }
  return nil
}

//aes generation

func (self *EgregoreSocket) genAES() error {
  b := make([]byte, 32)
  self.aesKey = make([]byte, 32)
  _, err := rand.Read(b)
  if err != nil {
    return err
  }
  copy(self.aesKey, b)
  return nil
}

//blowfish generation

func (self *EgregoreSocket) genBlowfish() error {
  b := make([]byte, 56)
  self.blowfishKey = make([]byte, 56)
  _, err := rand.Read(b)
  if err != nil {
    return err
  }
  copy(self.blowfishKey, b)
  return nil
}

//convertation

func (self *EgregoreSocket) convertRSAPublicKeyToBytes(index int) []byte {
  return x509.MarshalPKCS1PublicKey(&self.rsaKeyPair[index].PublicKey)
}

func (self *EgregoreSocket) convertBytesToRSAPublicKey(bytes [] byte, index int) error {
  key, err := x509.ParsePKCS1PublicKey(bytes)
  if err == nil {
      self.remoteRSAKey[index] = key
  }
  return err
}

func (self *EgregoreSocket) convertUint32ToBytes(value uint32) []byte {
    buf := make([]byte, 4)
    binary.BigEndian.PutUint32(buf, value)
    return buf
}

func (self *EgregoreSocket) convertBytesToUint32(bytes []byte) uint32 {
  return binary.BigEndian.Uint32(bytes)
}

//encryption

func (self *EgregoreSocket) encryptRSAMessage(msg []byte, index int) ([]byte, error) {
  return rsa.EncryptOAEP(sha512.New(), rand.Reader, self.remoteRSAKey[index], msg, nil)
}

func (self *EgregoreSocket) decryptRSAMessage(msg []byte, index int) ([]byte, error) {
  return rsa.DecryptOAEP(sha512.New(), rand.Reader, self.rsaKeyPair[index], msg, nil)
}

func (self *EgregoreSocket) encryptAESMessage(msg []byte, iv []byte) ([]byte, error) {
  result := make([]byte, len(msg))
  block, err := aes.NewCipher(self.aesKey)
  if err != nil {
      return nil, err
  }
  mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(result, msg)
  return result, nil
}

func (self *EgregoreSocket) decryptAESMessage(msg []byte, iv []byte) ([]byte, error) {
  result := make([]byte, len(msg))
  block, err := aes.NewCipher(self.remoteAESKey)
  if err != nil {
      return nil, err
  }
  mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(result, msg)
  return result, nil
}

func (self *EgregoreSocket) encryptBlowfishMessage(msg []byte, iv []byte) ([]byte, error) {
  result := make([]byte, len(msg))
  block, err := blowfish.NewCipher(self.blowfishKey)
  if err != nil {
      return nil, err
  }
  mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(result, msg)
  return result, nil
}

func (self *EgregoreSocket) decryptBlowfishMessage(msg []byte, iv []byte) ([]byte, error) {
  result := make([]byte, len(msg))
  block, err := blowfish.NewCipher(self.remoteBlowfishKey)
  if err != nil {
      return nil, err
  }
  mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(result, msg)
  return result, nil
}

//handshake

func (self *EgregoreSocket) hostHandshake() (bool, error) {
  var err error
  msg := make([]byte, len(ANSWER))
  _, err = self.socket.Read(msg)
  if err != nil {
    self.Log("Low level handshake error: " + err.Error() + ".")
    return false, err
  }
  status := (string(msg) == ANSWER)
  if status {
    self.Log("Right handshake answer.")
  } else {
    self.Log("Wrong handshake answer.")
  }
  return status, nil
}

func (self *EgregoreSocket) hostDecision(accept bool) error {
  signal := make([]byte, 1)
  if accept {
    signal[0] = YES
  } else {
    signal[0] = NO
  }
  _, err := self.socket.Write(signal)
  if err != nil {
    self.Log("Low level handshake error: " + err.Error() + ".")
    return err
  }
  if accept {
    self.Log("You accepted connection from (" + self.remoteAddr + ") to port " + strconv.Itoa(self.port) + ".")
  } else {
    self.Log("You rejected connection from (" + self.remoteAddr + ") to port " + strconv.Itoa(self.port) + ".")
  }
  return nil
}

func (self *EgregoreSocket) recieverHandshake() (bool, error) {
  var err error
  msg := make([]byte, 1)
  _, err = self.socket.Write([]byte(ANSWER))
  if err != nil {
    self.Log("Low level handshake error: " + err.Error() + ".")
    return false, err
  }
  _, err = self.socket.Read(msg)
  if err != nil {
    self.Log("Low level handshake error: " + err.Error() + ".")
    return false, err
  }
  if msg[0] == YES {
    self.Log("Your connection was accepted.")
    return true, nil
  } else if msg[0] == NO {
    self.Log("Your connection was rejected.")
    return false, nil
  } else {
    self.Log("Unknown answer for your connection.")
    return false, errors.New("Unknown answer")
  }
}

//key exchange

func (self *EgregoreSocket) keyExchange() error {
  self.Log("Key exchange was started. Please wait...")
  err := self.keyExchangeFirstStage()
  if err != nil {
    return err
  }
  err = self.keyExchangeSecondStage()
  if err != nil {
    return err
  }
  self.Log("Key exchange was successfully completed.")
  return nil
}

func (self *EgregoreSocket) sendRSAKey(i int) error {
  var err error
  self.Log("Sending RSA public key (" + strconv.Itoa(i + 1) + ") was started. Please wait...")
  err = self.sendRSAKeySupportFunc(i)
  if err != nil {
    self.Log("Sending RSA public key (" + strconv.Itoa(i + 1) + ") was failed. " + err.Error() + ".")
    return err
  }
  self.Log("Sending RSA public key (" + strconv.Itoa(i + 1) + ") was successfully completed.")
  return nil
}

func (self *EgregoreSocket) recvRSAKey(i int) error {
  var err error
  self.Log("Receiving RSA public key (" + strconv.Itoa(i + 1) + ") was started. Please wait...")
  err = self.recvRSAKeySupportFunc(i)
  if err != nil {
    self.Log("Receiving RSA public key (" + strconv.Itoa(i + 1) + ") was failed. " + err.Error() + ".")
    return err
  }
  self.Log("Receiving RSA public key (" + strconv.Itoa(i + 1) + ") was successfully completed.")
  return nil
}

func (self *EgregoreSocket) keyExchangeFirstStage() error {
  i := 0
  var err error
  self.Log("Public key exchange stage was started. Please wait...")
  if self.iAmHost {
    //host
    for i < 2 {
        err = self.sendRSAKey(i)
        if err != nil {
          return err
        }
        err = self.recvRSAKey(i)
        if err != nil {
          return err
        }
        i += 1
    }
  } else {
    //no host
    for i < 2 {
      err = self.recvRSAKey(i)
      if err != nil {
        return err
      }
      err = self.sendRSAKey(i)
      if err != nil {
        return err
      }
      i += 1
    }
  }
  self.Log("Public key exchange stage was successfully completed.")
  return nil
}

func (self *EgregoreSocket) sendAESKey() error {
  var err error
  self.Log("Sending AES key was started. Please wait...")
  err = self.sendAESKeySupportFunc()
  if err != nil {
    self.Log("Sending AES key was failed. " + err.Error() + ".")
    return err
  }
  self.Log("Sending AES key was successfully completed.")
  return nil
}

func (self *EgregoreSocket) recvAESKey() error {
  var err error
  self.Log("Receiving AES key was started. Please wait...")
  err = self.recvAESKeySupportFunc()
  if err != nil {
    self.Log("Receiving AES key was failed. " + err.Error() + ".")
    return err
  }
  self.Log("Receiving AES key was successfully completed.")
  return nil
}

func (self *EgregoreSocket) sendBlowfishKey() error {
  var err error
  self.Log("Sending Blowfish key was started. Please wait...")
  err = self.sendBlowfishKeySupportFunc()
  if err != nil {
    self.Log("Sending Blowfish key was failed. " + err.Error() + ".")
    return err
  }
  self.Log("Sending Blowfish key was successfully completed.")
  return nil
}

func (self *EgregoreSocket) recvBlowfishKey() error {
  var err error
  self.Log("Receiving Blowfish key was started. Please wait...")
  err = self.recvBlowfishKeySupportFunc()
  if err != nil {
    self.Log("Receiving Blowfish key was failed. " + err.Error() + ".")
    return err
  }
  self.Log("Receiving Blowfish key was successfully completed.")
  return nil
}


func (self *EgregoreSocket) keyExchangeSecondStage() error {
  var err error
  self.Log("Secret key exchange stage was started. Please wait...")
  if self.iAmHost {
    //host
    err = self.sendAESKey()
    if err != nil {
      return err
    }
    err = self.recvAESKey()
    if err != nil {
      return err
    }

    err = self.sendBlowfishKey()
    if err != nil {
      return err
    }
    err = self.recvBlowfishKey()
    if err != nil {
      return err
    }
  } else {
    //no host
    err = self.recvAESKey()
    if err != nil {
      return err
    }
    self.sendAESKey()

    err = self.recvBlowfishKey()
    if err != nil {
      return err
    }
    self.sendBlowfishKey()
  }
  self.Log("Secret key exchange stage was successfully completed.")
  return nil
}

//rsa key exchange

func (self *EgregoreSocket) sendRSAKeySupportFunc(index int) error {
  return self.sendMessage(self.convertRSAPublicKeyToBytes(index))
}

func (self *EgregoreSocket) recvRSAKeySupportFunc(index int) error {
  msg, err := self.recvMessage()
  if err == nil {
    return self.convertBytesToRSAPublicKey(msg, index)
  } else {
    return err
  }
}

//aes key exchange

func (self *EgregoreSocket) sendAESKeySupportFunc() error {
  msg, err := self.encryptRSAMessage(self.aesKey, 0)
  if err != nil {
    return err
  }
  err = self.sendMessage(msg)
  if err != nil {
    return err
  }
  return nil
}

func (self *EgregoreSocket) recvAESKeySupportFunc() error {
  msg, err := self.recvMessage()
  if err != nil {
    return err
  }
  msg, err = self.decryptRSAMessage(msg, 0)
  if err != nil {
    return err
  }
  self.SetRemoteAESKey(msg)
  return nil
}

//blowfish key exchange

func (self *EgregoreSocket) sendBlowfishKeySupportFunc() error {
  msg, err := self.encryptRSAMessage(self.blowfishKey, 1)
  if err != nil {
    return err
  }
  err = self.sendMessage(msg)
  if err != nil {
    return err
  }
  return nil
}

func (self *EgregoreSocket) recvBlowfishKeySupportFunc() error {
  msg, err := self.recvMessage()
  if err != nil {
    return err
  }
  msg, err = self.decryptRSAMessage(msg, 1)
  if err != nil {
    return err
  }
  self.SetRemoteBlowfishKey(msg)
  return nil
}

//support functions

func (self *EgregoreSocket) setFieldsOnConEvent(conn *net.TCPConn, iAmHost bool) {
  self.socket = conn
  self.waitForCon = false
  self.iAmHost = iAmHost
  self.alreadyCon = true
}

func (self *EgregoreSocket) encodeMessage(msg []byte) ([]byte, error) {
  result := append(msg, END)
  var err error
  n := len(result)
  rest := 16 - n % 16
  if rest != 0 {
    result = append(result, make([]byte, rest)...)
    i, k := n, n + rest
    r := make([]byte, 1)
    for i < k {
      r[0] = END
      for r[0] == END {
        _, err = rand.Read(r)
        if err != nil {
          return nil, err
        }
      }
      result[i] = r[0]
      i += 1
    }
  }
  return result, nil
}

func (self *EgregoreSocket) decodeMessage(msg []byte) ([]byte, error) {
  n := len(msg)
  if n == 0 {
    return nil, errors.New("Message is empty")
  }
  i, boundary := n - 1, n - 16
  pos := -1
  for i >= boundary {
    if msg[i] == END {
      pos = i
      break
    }
    i -= 1
  }
  if pos != -1 {
    return msg[:pos], nil
  } else {
    return nil, errors.New("Message end flag not found")
  }
}

func (self *EgregoreSocket) getMetaMesssageInfo(buf []byte) (uint32, byte) {
  return self.convertBytesToUint32(buf[:4]), buf[4]
}

func (self *EgregoreSocket) genIV() ([]byte, error) {
  iv := make([]byte, 16)
  _, err := rand.Read(iv)
  if err == nil {
    return iv, nil
  } else {
    return nil, err
  }
}

func (self *EgregoreSocket) AutoDecision() (bool, error) {
  return true, nil
}

func (self *EgregoreSocket) Log(s string) {
  if self.logFunc == nil {
    log.Println(s)
  } else {
    self.logFunc(s)
  }
}

func (self *EgregoreSocket) decision() (bool, error) {
  if self.decisionFunc == nil {
    return self.AutoDecision()
  } else {
    return self.decisionFunc()
  }
}
