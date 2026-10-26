package main

import (
	"bufio"
	"crypto/rand"
	"encoding/binary"
	"flag"
	"fmt"
	"os"
	"time"
)

// incomingMsg is a fully reassembled chat message from the listener goroutine.
type incomingMsg struct {
	Name string
	Text string
}

func main() {
	peer := flag.String("peer", "", "peer IP address (required)")
	name := flag.String("name", "anon", "your display name")
	keyPass := flag.String("key", "", "optional passphrase for payload encryption")
	flag.Parse()

	if *peer == "" {
		fmt.Fprintln(os.Stderr, "usage: icmpchat --peer <ip> [--name <nick>] [--key <passphrase>]")
		os.Exit(2)
	}

	var key []byte
	if *keyPass != "" {
		key = newKey(*keyPass)
	}

	sender, err := NewSender(*peer)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot open sender socket: %v\n", err)
		os.Exit(1)
	}
	defer sender.Close()

	var listener *Listener
	if l, err := NewListener(*peer, key); err != nil {
		fmt.Fprintf(os.Stderr, "receiving needs root: run with sudo (could not open raw ICMP socket: %v)\n", err)
		fmt.Fprintln(os.Stderr, "running in send-only mode; enable receiving with sudo.")
	} else {
		listener = l
		defer listener.Close()
	}

	incoming := make(chan incomingMsg)
	lines := make(chan string)

	if listener != nil {
		go listenLoop(listener, incoming)
	}
	go inputLoop(lines)

	fmt.Printf("icmpchat: chatting as %q, peer %s\n", *name, *peer)
	if key != nil {
		fmt.Println("payload encryption: on")
	} else {
		fmt.Println("payload encryption: off")
	}

	fmt.Print("> ")
	for {
		select {
		case msg, ok := <-incoming:
			if !ok {
				continue
			}
			printIncoming(msg)
		case line, ok := <-lines:
			if !ok {
				fmt.Println()
				return
			}
			if line == "" {
				fmt.Print("> ")
				continue
			}
			sendLine(line, *peer, *name, key, sender)
		}
	}
}

func inputLoop(lines chan<- string) {
	scanner := bufio.NewReader(os.Stdin)
	for {
		line, err := scanner.ReadString('\n')
		cleaned := trimLineEndings(line)
		if cleaned != "" {
			lines <- cleaned
		}
		if err != nil {
			close(lines)
			return
		}
	}
}

func listenLoop(l *Listener, incoming chan<- incomingMsg) {
	for {
		msgName, text, ok, err := l.ReadNext()
		if err != nil {
			continue
		}
		if ok {
			incoming <- incomingMsg{Name: msgName, Text: text}
		}
	}
}

// printIncoming renders a received message on its own line above the prompt.
func printIncoming(msg incomingMsg) {
	ts := time.Now().Format("15:04:05")
	fmt.Printf("\n%s %s: %s\n", ts, msg.Name, msg.Text)
	fmt.Print("> ")
}

// sendLine encodes and transmits one chat message, chunking long text, and
// reports delivery per transmitted chunk.
func sendLine(line, peer, name string, key []byte, sender *Sender) {
	chunks, cnt, err := chunkText(name, line, key)
	if err != nil {
		fmt.Println("✗ (message too long)")
		return
	}
	msgID := randMsgID()
	for i, c := range chunks {
		m := &Message{
			Name:     name,
			Text:     string(c),
			MsgID:    msgID,
			ChunkIdx: uint8(i),
			ChunkCnt: cnt,
		}
		payload, err := encode(m, key)
		if err != nil {
			fmt.Println("✗ (encode error)")
			return
		}
		if sender.Send(payload) {
			fmt.Println("✓")
		} else {
			fmt.Println("✗ (no reply)")
			return
		}
	}
}

func randMsgID() uint32 {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return uint32(time.Now().UnixNano())
	}
	return binary.BigEndian.Uint32(b[:])
}

func trimLineEndings(line string) string {
	for len(line) > 0 {
		last := line[len(line)-1]
		if last == '\n' || last == '\r' {
			line = line[:len(line)-1]
			continue
		}
		break
	}
	return line
}
