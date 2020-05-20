package decrypt

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"reflect"
	"runtime/debug"
)

// https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/message-format.html

type kmsMessage struct {
	header kmsMessageHeader
	body   kmsMessageBody
	footer kmsMessageFooter
}

const (
	kmsMessageContentTypeNonFramed uint8 = 0x01
	kmsMessageContentTypeFramed          = 0x02
)

type kmsMessageHeader struct {
	version     uint8
	kind        uint8
	algID       uint16
	msgID       []byte
	aadLen      uint16
	aad         []byte
	keyCount    uint16
	keys        []kmsMessageKey
	contentType uint8
	reserved    uint32
	ivLen       uint8
	frameLen    uint32
	iv          []byte
	authTag     []byte
}

type kmsMessageKey struct {
	providerIDLen uint16
	providerID    []byte
	infoLen       uint16
	info          []byte
	keyLen        uint16
	key           []byte
}

type kmsMessageBody struct {
	frames []kmsMessageFrame
}

type kmsMessageBodyAADContent []byte

var (
	kmsMessageBodyFrameAAD      kmsMessageBodyAADContent = []byte("AWSKMSEncryptionClient Frame")
	kmsMessageBodyFinalFrameAAD                          = []byte("AWSKMSEncryptionClient Final Frame")
)

type kmsMessageFrame struct {
	seqNum        uint32
	iv            []byte
	contentLength uint32
	content       []byte
	authTag       []byte
	aad           kmsMessageBodyAADContent
}

type kmsMessageFooter struct {
	sigLen uint16
	sig    []byte
}

func newKMSMessage(in []byte) (m *kmsMessage, err error) {
	m = &kmsMessage{}
	defer func() {
		if r := recover(); r != nil {
			var ok bool
			if err, ok = r.(error); !ok {
				err = fmt.Errorf("panic: %v", r)
			}
		}
	}()

	buf := bytes.NewBufferString(string(in))

	readInto := func(field interface{}) {
		if err := binary.Read(buf, binary.BigEndian, field); err != nil {
			panic(fmt.Errorf("%+v\n%s", err, debug.Stack()))
		}
	}
	readIntoBytes := func(len uint64, field *[]byte) {
		arr := make([]byte, len)
		readInto(arr)
		reflect.ValueOf(field).Elem().Set(reflect.ValueOf(arr))
	}
	readIntoVarBytes := func(lenField interface{}, arrField *[]byte) {
		readInto(lenField)
		lenVal := reflect.Indirect(reflect.ValueOf(lenField))
		if !lenVal.Type().ConvertibleTo(reflect.TypeOf(uint64(0))) {
			panic(fmt.Errorf("lenField was not of number type. Was %v.\n%s", lenVal.Type(), debug.Stack()))
		}
		len := lenVal.Convert(reflect.TypeOf(uint64(0))).Uint()
		readIntoBytes(len, arrField)
	}
	// Read header.
	readInto(&m.header.version)
	readInto(&m.header.kind)
	readInto(&m.header.algID)
	readIntoBytes(16, &m.header.msgID)
	readIntoVarBytes(&m.header.aadLen, &m.header.aad)
	readInto(&m.header.keyCount)
	m.header.keys = make([]kmsMessageKey, m.header.keyCount)
	for i, k := range m.header.keys {
		readIntoVarBytes(&k.providerIDLen, &k.providerID)
		readIntoVarBytes(&k.infoLen, &k.info)
		readIntoVarBytes(&k.keyLen, &k.key)
		m.header.keys[i] = k
	}
	readInto(&m.header.contentType)
	readInto(&m.header.reserved)
	readInto(&m.header.ivLen)
	readInto(&m.header.frameLen)
	alg, err := getAlgorithmByID(m.header.algID)
	if err != nil {
		return
	}
	readIntoBytes(alg.ivLen, &m.header.iv)
	readIntoBytes(alg.authTagLen, &m.header.authTag)

	// Read body.
	if m.header.contentType != kmsMessageContentTypeFramed {
		err = errors.New("unable to handle unframed body")
		return
	}
	finalFrame := false
	for !finalFrame {
		frame := kmsMessageFrame{}
		readInto(&frame.seqNum)
		finalFrame = bool(frame.seqNum == 0xFFFFFFFF)
		if !finalFrame {
			readIntoBytes(uint64(m.header.ivLen), &frame.iv)
			frame.contentLength = m.header.frameLen
			readIntoBytes(uint64(m.header.frameLen), &frame.content)
			readIntoBytes(alg.authTagLen, &frame.authTag)
			frame.aad = kmsMessageBodyFrameAAD
		} else {
			readInto(&frame.seqNum)
			readIntoBytes(uint64(m.header.ivLen), &frame.iv)
			readIntoVarBytes(&frame.contentLength, &frame.content)
			readIntoBytes(alg.authTagLen, &frame.authTag)
			frame.aad = kmsMessageBodyFinalFrameAAD
		}
		m.body.frames = append(m.body.frames, frame)
	}

	// Read footer.
	readIntoVarBytes(&m.footer.sigLen, &m.footer.sig)
	return
}

func (b kmsMessage) getHKDFInfo() []byte {
	var buf bytes.Buffer
	binary.Write(&buf, binary.BigEndian, b.header.algID)
	binary.Write(&buf, binary.BigEndian, b.header.msgID)
	return buf.Bytes()
}

func (b kmsMessage) getAAD(frameIndex int) []byte {
	f := b.body.frames[frameIndex]
	var buf bytes.Buffer
	binary.Write(&buf, binary.BigEndian, b.header.msgID)
	binary.Write(&buf, binary.BigEndian, f.aad)
	binary.Write(&buf, binary.BigEndian, f.seqNum)
	binary.Write(&buf, binary.BigEndian, uint32(0))
	binary.Write(&buf, binary.BigEndian, f.contentLength)
	return buf.Bytes()
}
