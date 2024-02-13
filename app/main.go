package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
)

type DNSHeader struct {
	ID      uint16 //(16 bits) Packet Identifier       : Packet Identifier
	QR      uint8  //(1 bit)   Query/Response indicator: 1 = reply packet, 0 = question packet
	OPCODE  uint8  //(4 bits)  Operation Code		     : Specifies kind of query
	AA      uint8  //(1 bit)   Authoritative Answer    : 1 = responding server "owns" the queried domain, 0 = otherwise
	TC      uint8  //(1 bit)   Truncation              : 1 = message larger than 512 bytes, 0 = otherwise
	RD      uint8  //(1 bit)   Recursion Desired       : 1 = recursively solve query, 0 = otherwise
	RA      uint8  //(1 bit)   Recursion Available     : 1 = recursion available, 0 = otherwise
	Z       uint8  //(3 bits)  Reserved                : Used by DNSSEC queries
	RCODE   uint8  //(4 bits)  Response Code           : Indicating the status of the response
	QDCOUNT uint16 //(16 bits) Question Count          : Number of questions in the Question section
	ANCOUNT uint16 //(16 bits) Answer Record Count     : Number of records in the Answer section
	NSCOUNT uint16 //(16 bits) Authority Record Count  : Number of records in the Authority section
	ARCOUNT uint16 //(16 bits) Additional Record Count : Number of records in the Additional section
}

type DNSQuestion struct {
	QNAME  string
	QTYPE  uint16
	QCLASS uint16
}

type DNSAnswer struct {
	NAME     string
	TYPE     uint16
	CLASS    uint16
	TTL      uint32
	RDLENGTH uint16
	RDATA    []byte
}

type DNSMessage struct {
	Header   DNSHeader
	Question []DNSQuestion
	Answer   []DNSAnswer
}

func SerializeDNSName(name string) ([]byte, error) {
	labels := strings.Split(name, ".")
	data := []byte{}

	for _, label := range labels {
		data = append(data, byte(len(label)))
		data = append(data, label...)
	}

	data = append(data, '\x00')
	return data, nil

}

func (q *DNSQuestion) Serialize() []byte {
	labels, err := SerializeDNSName(q.QNAME)
	if err != nil {
		fmt.Println("Error when serializing DNS question name: ", err)
		return nil
	}
	size := len(labels) + 4
	bytes := make([]byte, size)

	copy(bytes, labels)

	bytes[size-4] = byte(q.QTYPE >> 8)
	bytes[size-3] = byte(q.QTYPE)
	bytes[size-2] = byte(q.QCLASS >> 8)
	bytes[size-1] = byte(q.QCLASS)

	return bytes
}

func (a *DNSAnswer) Serialize() ([]byte, error) {
	var buf bytes.Buffer
	name, _ := SerializeDNSName(a.NAME)
	buf.Write(name)
	err := binary.Write(&buf, binary.BigEndian, a.TYPE)
	if err != nil {
		return nil, fmt.Errorf("unable to write answer TYPE: %w", err)
	}
	err = binary.Write(&buf, binary.BigEndian, a.CLASS)
	if err != nil {
		return nil, fmt.Errorf("unable to write answer CLASS: %w", err)
	}
	err = binary.Write(&buf, binary.BigEndian, a.TTL)
	if err != nil {
		return nil, fmt.Errorf("unable to write answer TTL: %w", err)
	}
	err = binary.Write(&buf, binary.BigEndian, a.RDLENGTH)
	if err != nil {
		return nil, fmt.Errorf("unable to write answer RDLENGTH: %w", err)
	}

	buf.Write(a.RDATA)
	return buf.Bytes(), nil
}

func (h *DNSHeader) Serialize() []byte {
	buffer := make([]byte, 12)
	binary.BigEndian.PutUint16(buffer[0:2], h.ID)
	buffer[2] = h.QR<<7 | h.OPCODE<<3 | h.AA<<2 | h.TC<<1 | h.RD
	buffer[3] = h.RA<<7 | h.Z<<4 | h.RCODE
	binary.BigEndian.PutUint16(buffer[4:6], h.QDCOUNT)
	binary.BigEndian.PutUint16(buffer[6:8], h.ANCOUNT)
	binary.BigEndian.PutUint16(buffer[8:10], h.NSCOUNT)
	binary.BigEndian.PutUint16(buffer[10:12], h.ARCOUNT)
	return buffer
}

func (m *DNSMessage) Serialize() ([]byte, error) {
	data := []byte{}

	data = append(data, m.Header.Serialize()...)

	for _, q := range m.Question {
		data = append(data, q.Serialize()...)
	}

	for _, a := range m.Answer {
		answer, err := a.Serialize()
		if err != nil {
			return nil, fmt.Errorf("unable to write answer %w", err)
		}
		data = append(data, answer...)
	}
	return data, nil
}

func ParseDNSHeader(r *bytes.Reader) (DNSHeader, error) {
	h := DNSHeader{}
	//Read ID (2 bytes)
	binary.Read(r, binary.BigEndian, &h.ID)
	//Read QR, OPCODE, AA, TC, RD (1 byte)
	thirdByteFlags, err := r.ReadByte()
	if err != nil {
		return h, fmt.Errorf("error reading DNS header on 3rd byte %w", err)
	}
	h.QR = thirdByteFlags >> 7
	h.OPCODE = (thirdByteFlags >> 3) & 0x0F
	h.AA = (thirdByteFlags >> 2) & 0x01
	h.TC = (thirdByteFlags >> 1) & 0x01
	h.RD = thirdByteFlags & 0x01

	//Read RA, RCODE (1 byte)
	fourthByteFlags, err := r.ReadByte()
	if err != nil {
		return h, fmt.Errorf("error reading DNS header on 4th byte %w", err)
	}
	h.RA = fourthByteFlags >> 7
	h.RCODE = fourthByteFlags & 0xF

	//Read QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT
	binary.Read(r, binary.BigEndian, &h.QDCOUNT)
	binary.Read(r, binary.BigEndian, &h.ANCOUNT)
	binary.Read(r, binary.BigEndian, &h.NSCOUNT)
	binary.Read(r, binary.BigEndian, &h.ARCOUNT)

	return h, nil
}

func ParseDNSName(r *bytes.Reader) (string, error) {
	var name string
	var length byte
	for {
		err := binary.Read(r, binary.BigEndian, &length)
		if err != nil {
			return "", fmt.Errorf("error reading DNS question name length %w", err)
		}
		if length == 0 {
			break
		}
		labels := make([]byte, length)
		_, err = r.Read(labels)
		if err != nil {
			return "", fmt.Errorf("error reading DNS question name label %w", err)
		}
		if len(name) > 0 {
			name += "."
		}
		name += string(labels)
	}
	return name, nil
}

func ParseDNSQuestion(r *bytes.Reader) (DNSQuestion, error) {
	q := DNSQuestion{}
	name, _ := ParseDNSName(r)
	q.QNAME = name
	binary.Read(r, binary.BigEndian, q.QTYPE)
	binary.Read(r, binary.BigEndian, q.QCLASS)

	return q, nil
}

func CreateDNSMessage(request *DNSMessage) (DNSMessage, error) {
	response := DNSMessage{}
	//process question
	questions := []DNSQuestion{}
	for i := 0; i < int(request.Header.QDCOUNT); i++ {
		q := DNSQuestion{
			QNAME:  request.Question[i].QNAME,
			QTYPE:  1,
			QCLASS: 1,
		}
		questions = append(questions, q)
	}
	response.Question = questions

	//process answer
	answers := []DNSAnswer{}
	for i := 0; i < int(request.Header.QDCOUNT); i++ {
		a := DNSAnswer{
			NAME:     request.Question[i].QNAME,
			TYPE:     1,
			CLASS:    1,
			TTL:      60,
			RDLENGTH: 4,
			RDATA:    []byte{8, 8, 8, 8},
		}
		answers = append(answers, a)
	}
	response.Answer = answers

	//process header
	if request.Header.OPCODE == 0 {
		response.Header.RCODE = 0
	} else {
		response.Header.RCODE = 4
	}

	response.Header = DNSHeader{
		ID:      request.Header.ID,
		QR:      1,
		OPCODE:  request.Header.OPCODE,
		AA:      0,
		TC:      0,
		RD:      request.Header.RD,
		RA:      0,
		Z:       0,
		RCODE:   response.Header.RCODE,
		QDCOUNT: uint16(len(questions)),
		ANCOUNT: uint16(len(answers)),
		NSCOUNT: 0,
		ARCOUNT: 0,
	}

	return response, nil
}

func ParseDNSMessage(r *bytes.Reader) (DNSMessage, error) {
	header, err := ParseDNSHeader(r)
	if err != nil {
		fmt.Println("Error reading DNS message, returning empty message ", err)
		return DNSMessage{}, err
	}
	//parse incoming question
	_, _ = r.Seek(12, io.SeekStart)
	questions := []DNSQuestion{}
	for i := 0; i < int(header.QDCOUNT); i++ {
		var q DNSQuestion
		name, _ := ParseDNSName(r)
		q.QNAME = name
		binary.Read(r, binary.BigEndian, q.QTYPE)
		binary.Read(r, binary.BigEndian, q.QCLASS)
		questions = append(questions, q)
	}

	return DNSMessage{
		Header:   header,
		Question: questions,
	}, nil
}

func main() {
	// You can use print statements as follows for debugging, they'll be visible when running tests.
	fmt.Println("Logs from your program will appear here!")

	udpAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:2053")
	if err != nil {
		fmt.Println("Failed to resolve UDP address:", err)
		return
	}

	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		fmt.Println("Failed to bind to address:", err)
		return
	}
	defer udpConn.Close()

	buf := make([]byte, 512)

	for {
		// Read from incoming DNS packets
		size, source, err := udpConn.ReadFromUDP(buf)
		if err != nil {
			fmt.Println("Error receiving data:", err)
			break
		}

		receivedData := string(buf[:size])
		fmt.Printf("Received %d bytes from %s: %s\n", size, source, receivedData)

		dataReader := bytes.NewReader(buf[:size])
		parsedData, err := ParseDNSMessage(dataReader)
		if err != nil {
			fmt.Println("error while parsing DNS message ", err)
			continue
		}

		// Create example header with question & answer for response
		// exampleQuestion := []DNSQuestion{
		// 	{QNAME: "codecrafters.io",
		// 		QTYPE:  1,
		// 		QCLASS: 1,
		// 	}}

		// exampleAnswer := []DNSAnswer{{
		// 	NAME:     "codecrafters.io",
		// 	TYPE:     1,
		// 	CLASS:    1,
		// 	TTL:      60,
		// 	RDLENGTH: 4,
		// 	RDATA:    []byte{8, 8, 8, 8},
		// }}

		// if parsedData.Header.OPCODE == 0 {
		// 	parsedData.Header.RCODE = 0
		// } else {
		// 	parsedData.Header.RCODE = 4

		// }

		// exampleHeader := DNSHeader{
		// 	ID:      parsedData.Header.ID,
		// 	QR:      1,
		// 	OPCODE:  parsedData.Header.OPCODE,
		// 	AA:      0,
		// 	TC:      0,
		// 	RD:      parsedData.Header.RD,
		// 	RA:      0,
		// 	Z:       0,
		// 	RCODE:   parsedData.Header.RCODE,
		// 	QDCOUNT: 1,
		// 	ANCOUNT: 1,
		// 	NSCOUNT: 0,
		// 	ARCOUNT: 0,
		// }

		// exampleMessage := DNSMessage{
		// 	Header:   exampleHeader,
		// 	Question: exampleQuestion,
		// 	Answer:   exampleAnswer,
		// }

		exampleMessage, err := CreateDNSMessage(&parsedData)
		if err != nil {
			fmt.Println("Failed to create DNS message: ", err)
		}

		receivedMessage, err := exampleMessage.Serialize()
		if err != nil {
			fmt.Println("Failed to serialize message: ", err)
		}

		_, err = udpConn.WriteToUDP(receivedMessage, source)
		if err != nil {
			fmt.Println("Failed to send response:", err)
		}
	}
}
