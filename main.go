package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"time"

	"icmpchat/internal/icmpchat"
)

// incomingMsg is a fully reassembled chat message from the listener goroutine.
type incomingMsg struct {
	Name string
	Text string
}

func main() {
	peer := flag.String("peer", "", "peer IP address (required for direct mode)")
	name := flag.String("name", "anon", "your display name")
	keyPass := flag.String("key", "", "optional passphrase for payload encryption")
	relay := flag.String("relay", "", "relay server IP; when set, messages are routed through it for one-to-many chat")
	room := flag.String("room", "lobby", "chat room to join when relaying")
	flag.Parse()

	if *peer == "" && *relay == "" {
		fmt.Fprintln(os.Stderr, "usage: icmpchat [--peer <ip> | --relay <ip>] [--name <nick>] [--room <name>] [--key <passphrase>]")
		os.Exit(2)
	}

	var key []byte
	if *keyPass != "" {
		key = icmpchat.NewKey(*keyPass)
	}

	// overhead is the relay routing header added in front of each chunk when
	// relaying, so chunking keeps the total ICMP payload within the limit.
	overhead := 0
	relayRoom := *room
	if *relay != "" {
		overhead = icmpchat.RelayHeaderLen(relayRoom)
	}

	sender, err := icmpchat.NewSender(sendTarget(*peer, *relay))
	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot open sender socket: %v\n", err)
		os.Exit(1)
	}
	defer sender.Close()

	var listener *icmpchat.Listener
	if l, err := icmpchat.NewListener(*peer, *relay, key); err != nil {
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

	// In relay mode, poll the relay every second. A poll is a keepalive that
	// joins the room and asks the relay to drain any messages queued since the
	// last poll as an echo reply. This is how clients that cannot receive echo
	// requests (such as macOS) learn of queued messages.
	if *relay != "" {
		pollPayload, err := icmpchat.BuildPollHeader(relayRoom)
		if err != nil {
			fmt.Fprintf(os.Stderr, "cannot build poll header: %v\n", err)
			os.Exit(1)
		}
		go pollLoop(sender, pollPayload)
	}
	if *relay != "" {
		fmt.Printf("icmpchat: chatting as %q via relay %s, room %q\n", *name, *relay, relayRoom)
	} else {
		fmt.Printf("icmpchat: chatting as %q, peer %s\n", *name, *peer)
	}
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
			sendLine(line, *name, key, sender, *relay, relayRoom, overhead)
		}
	}
}

// pollInterval is how often a relay client polls the relay. Each poll is a
// keepalive that joins the room and drains queued messages.
const pollInterval = time.Second

// pollLoop sends a keepalive poll to the relay every pollInterval. It drives
// pull-based delivery: the relay queues messages for a member and hands them
// out as echo replies on the member's next poll, which is how clients that
// cannot receive echo requests (such as macOS) get their messages.
func pollLoop(sender *icmpchat.Sender, pollPayload []byte) {
	// Poll immediately so the room joins without waiting for the first tick, then
	// keep polling to stay registered and drain queued messages.
	if !sender.SendPoll(pollPayload) {
		fmt.Fprintf(os.Stderr, "icmpchat: initial poll failed\n")
	} else {
		fmt.Fprintf(os.Stderr, "icmpchat: initial poll sent\n")
	}
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()
	count := 0
	for range ticker.C {
		count++
		if !sender.SendPoll(pollPayload) {
			fmt.Fprintf(os.Stderr, "icmpchat: poll failed\n")
		} else {
			fmt.Fprintf(os.Stderr, "icmpchat: poll #%d sent\n", count)
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

func listenLoop(l *icmpchat.Listener, incoming chan<- incomingMsg) {
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
// reports delivery per transmitted chunk. When relay is set, each chunk is
// wrapped in a visible relay routing header for the given room.
func sendLine(line, name string, key []byte, sender *icmpchat.Sender, relay, room string, overhead int) {
	chunks, cnt, err := icmpchat.ChunkText(name, line, key, overhead)
	if err != nil {
		fmt.Println("✗ (message too long)")
		return
	}
	msgID := icmpchat.RandMsgID()
	for i, c := range chunks {
		m := &icmpchat.Message{
			Name:     name,
			Text:     string(c),
			MsgID:    msgID,
			ChunkIdx: uint8(i),
			ChunkCnt: cnt,
		}
		chatPayload, err := icmpchat.Encode(m, key)
		if err != nil {
			fmt.Println("✗ (encode error)")
			return
		}
		var payload []byte
		if relay != "" {
			header, err := icmpchat.BuildRelayHeader(room)
			if err != nil {
				fmt.Printf("✗ (relay header: %v)\n", err)
				return
			}
			payload = make([]byte, 0, len(header)+len(chatPayload))
			payload = append(payload, header...)
			payload = append(payload, chatPayload...)
		} else {
			payload = chatPayload
		}
		if sender.Send(payload) {
			fmt.Println("✓")
		} else {
			fmt.Println("✗ (no reply)")
			return
		}
	}
}

// sendTarget returns the destination IP for outgoing packets: the relay when
// relaying, otherwise the direct peer.
func sendTarget(peer, relay string) string {
	if relay != "" {
		return relay
	}
	return peer
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
