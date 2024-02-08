package main

import (
	"encoding/binary"
	"fmt"
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

type DNSMessage struct {
	Header   DNSHeader
	Question DNSQuestion
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

func (q *DNSQuestion) SerializeName() []byte {
	labels := strings.Split(q.QNAME, ".")
	data := []byte{}

	for _, label := range labels {
		data = append(data, byte(len(label)))
		data = append(data, label...)
	}

	data = append(data, '\x00')
	return data
}

func (q *DNSQuestion) Serialize() []byte {
	labels := q.SerializeName()
	size := len(labels) + 4
	bytes := make([]byte, size)

	copy(bytes, labels)

	bytes[size-4] = byte(q.QTYPE >> 8)
	bytes[size-3] = byte(q.QTYPE)
	bytes[size-2] = byte(q.QCLASS >> 8)
	bytes[size-1] = byte(q.QCLASS)

	return bytes
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
		size, source, err := udpConn.ReadFromUDP(buf)
		if err != nil {
			fmt.Println("Error receiving data:", err)
			break
		}

		receivedData := string(buf[:size])
		fmt.Printf("Received %d bytes from %s: %s\n", size, source, receivedData)

		// Create an empty response
		//response := []byte{}

		// Create example header & question
		exampleHeader := DNSHeader{
			ID:      1234,
			QR:      1,
			OPCODE:  0,
			AA:      0,
			TC:      0,
			RD:      0,
			RA:      0,
			Z:       0,
			RCODE:   0,
			QDCOUNT: 1,
			ANCOUNT: 0,
			NSCOUNT: 0,
			ARCOUNT: 0,
		}
		exampleQuestion := DNSQuestion{
			QNAME:  "codecrafters.io",
			QTYPE:  1,
			QCLASS: 1,
		}
		var response []byte
		response = append(response, exampleHeader.Serialize()...)
		response = append(response, exampleQuestion.Serialize()...)

		//response := exampleHeader.Serialize()

		_, err = udpConn.WriteToUDP(response, source)
		if err != nil {
			fmt.Println("Failed to send response:", err)
		}
	}
}
