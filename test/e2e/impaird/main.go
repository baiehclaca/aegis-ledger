// Command impaird forwards Ethernet frames between veth pairs and, when
// switched on, applies delay, jitter, loss, and reorder.
//
// The test kernel is built with CONFIG_NET_SCH_NETEM unset, so tc cannot
// attach a netem qdisc. This process is the stand-in used by the multi-host
// tests. Parameters match a tc-netem invocation of
// "delay 20ms 5ms loss 1% reorder 5% 50%". The correlated reorder draw is an
// approximation of the kernel's fixed-point walk, not a bit-identical port.
package main

import (
	"bufio"
	"container/heap"
	"flag"
	"fmt"
	"math/rand/v2"
	"net"
	"os"
	"strings"
	"syscall"
	"time"
)

const (
	packetIgnoreOutgoing = 23
	frameHeader          = 14
	frameBuf             = 65536
	queueCap             = 4096
	tick                 = time.Millisecond
)

func main() {
	ctrl := flag.String("ctrl", "", "unix socket that accepts on and off")
	host := flag.String("host", "", "veth peer of the host address; ingress is not impaired")
	nodes := flag.String("nodes", "", "comma-separated node veth names")
	pidfile := flag.String("pidfile", "", "file that receives this process id")
	delay := flag.Duration("delay", 20*time.Millisecond, "base delay applied to node egress")
	jitter := flag.Duration("jitter", 5*time.Millisecond, "symmetric delay jitter")
	loss := flag.Float64("loss", 0.01, "independent drop probability")
	reorderP := flag.Float64("reorder", 0.05, "probability a frame skips the delay")
	correlation := flag.Float64("correlation", 0.5, "reorder correlation in [0,1]")
	flag.Parse()
	if err := serve(*ctrl, *host, *nodes, *pidfile, *delay, *jitter, *loss, *reorderP, *correlation); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func serve(ctrl, host, nodes, pidfile string, delay, jitter time.Duration, loss, reorderP, correlation float64) error {
	if ctrl == "" || host == "" || nodes == "" || pidfile == "" {
		return fmt.Errorf("impaird: ctrl, host, nodes, and pidfile are required")
	}
	if delay < 0 || jitter < 0 || loss < 0 || loss > 1 || reorderP < 0 || reorderP > 1 || correlation < 0 || correlation > 1 {
		return fmt.Errorf("impaird: delay, jitter, loss, reorder, or correlation out of range")
	}
	names := splitComma(nodes)
	if len(names) == 0 {
		return fmt.Errorf("impaird: no node interfaces")
	}
	ports := make([]port, 0, len(names)+1)
	hostPort, err := openPort(host)
	if err != nil {
		return err
	}
	ports = append(ports, hostPort)
	for _, name := range names {
		p, err := openPort(name)
		if err != nil {
			return err
		}
		ports = append(ports, p)
	}
	if err := os.WriteFile(pidfile, []byte(fmt.Sprintf("%d\n", os.Getpid())), 0o644); err != nil {
		return err
	}
	in := make(chan inbound, 256)
	for i := range ports {
		go readPort(ports[i], i, i != 0, in)
	}
	commands := make(chan bool, 4)
	if err := serveCtrl(ctrl, commands); err != nil {
		return err
	}
	fmt.Println("impair ready")
	runBridge(ports, in, commands, delay, jitter, loss, reorderP, correlation)
	return nil
}

type port struct {
	fd    int
	index int
}

type inbound struct {
	from  int
	node  bool
	frame []byte
}

type queued struct {
	when  time.Time
	from  int
	frame []byte
}

type queue []*queued

func (q queue) Len() int { return len(q) }

func (q queue) Less(i, j int) bool { return q[i].when.Before(q[j].when) }

func (q queue) Swap(i, j int) { q[i], q[j] = q[j], q[i] }

func (q *queue) Push(v any) { *q = append(*q, v.(*queued)) }

func (q *queue) Pop() any {
	old := *q
	n := len(old)
	item := old[n-1]
	old[n-1] = nil
	*q = old[:n-1]
	return item
}

func runBridge(ports []port, in <-chan inbound, commands <-chan bool, delay, jitter time.Duration, loss, reorderP, correlation float64) {
	b := &bridge{
		ports:   ports,
		delay:   delay,
		jitter:  jitter,
		loss:    loss,
		reorder: correlated{p: reorderP, c: correlation},
		rng:     rand.New(rand.NewPCG(1, 2)),
		mac:     make(map[[6]byte]int),
	}
	heap.Init(&b.q)
	tick := time.NewTicker(tick)
	defer tick.Stop()
	for {
		select {
		case frame := <-in:
			// A full delay queue used to discard the frame. With impairment
			// off, every frame is already due, so flushing makes room and
			// the partition phase does not add its own loss.
			if b.q.Len() >= queueCap {
				b.flush()
			}
			b.admit(frame)
		case <-tick.C:
			b.flush()
		case on := <-commands:
			b.on = on
		}
	}
}

type bridge struct {
	ports   []port
	on      bool
	delay   time.Duration
	jitter  time.Duration
	loss    float64
	reorder correlated
	rng     *rand.Rand
	mac     map[[6]byte]int
	q       queue
}

func (b *bridge) admit(frame inbound) {
	if len(frame.frame) < frameHeader {
		return
	}
	src := macOf(frame.frame[6:12])
	b.mac[src] = frame.from
	when := time.Now()
	if b.on && frame.node {
		if b.rng.Float64() < b.loss {
			return
		}
		d := b.delay
		if b.jitter > 0 {
			span := int64(b.jitter)*2 + 1
			d += time.Duration(b.rng.Int64N(span)) - b.jitter
		}
		if d < 0 {
			d = 0
		}
		when = when.Add(d)
		if b.reorder.hit(b.rng) {
			when = time.Now()
		}
	}
	if b.q.Len() >= queueCap {
		return
	}
	heap.Push(&b.q, &queued{when: when, from: frame.from, frame: frame.frame})
}

func (b *bridge) flush() {
	now := time.Now()
	for b.q.Len() > 0 {
		item := b.q[0]
		if item.when.After(now) {
			return
		}
		heap.Pop(&b.q)
		b.forward(item.from, item.frame)
	}
}

func (b *bridge) forward(from int, frame []byte) {
	dst := macOf(frame[0:6])
	if dst[0]&1 == 0 {
		if idx, ok := b.mac[dst]; ok && idx != from {
			b.write(idx, frame)
			return
		}
	}
	for i := range b.ports {
		if i == from {
			continue
		}
		b.write(i, frame)
	}
}

func (b *bridge) write(idx int, frame []byte) {
	sa := &syscall.SockaddrLinklayer{
		Protocol: htons(syscall.ETH_P_ALL),
		Ifindex:  b.ports[idx].index,
	}
	_ = syscall.Sendto(b.ports[idx].fd, frame, 0, sa)
}

type correlated struct {
	p, c float64
	last bool
}

func (c *correlated) hit(rng *rand.Rand) bool {
	thresh := c.p * (1 - c.c)
	if c.last {
		thresh = c.p + c.c*(1-c.p)
	}
	c.last = rng.Float64() < thresh
	return c.last
}

func readPort(p port, from int, node bool, out chan<- inbound) {
	buf := make([]byte, frameBuf)
	for {
		n, _, err := syscall.Recvfrom(p.fd, buf, 0)
		if err != nil || n < frameHeader {
			continue
		}
		frame := make([]byte, n)
		copy(frame, buf[:n])
		// Block when the bridge is behind. Discarding here is loss with
		// impairment off. TCP then sees a drop the partition did not ask
		// for, and a view that already sent its one timeout never hears
		// a certificate.
		out <- inbound{from: from, node: node, frame: frame}
	}
}

func openPort(name string) (port, error) {
	iff, err := net.InterfaceByName(name)
	if err != nil {
		return port{}, err
	}
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(syscall.ETH_P_ALL)))
	if err != nil {
		return port{}, err
	}
	sa := &syscall.SockaddrLinklayer{Protocol: htons(syscall.ETH_P_ALL), Ifindex: iff.Index}
	if err := syscall.Bind(fd, sa); err != nil {
		_ = syscall.Close(fd)
		return port{}, err
	}
	if err := syscall.SetsockoptInt(fd, syscall.SOL_PACKET, packetIgnoreOutgoing, 1); err != nil {
		_ = syscall.Close(fd)
		return port{}, err
	}
	return port{fd: fd, index: iff.Index}, nil
}

func serveCtrl(path string, commands chan<- bool) error {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return err
	}
	if err := os.Chmod(path, 0o777); err != nil {
		return err
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			sc := bufio.NewScanner(conn)
			for sc.Scan() {
				switch strings.TrimSpace(sc.Text()) {
				case "on":
					commands <- true
				case "off":
					commands <- false
				}
			}
			_ = conn.Close()
		}
	}()
	return nil
}

func splitComma(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func htons(v uint16) uint16 { return v<<8 | v>>8 }

func macOf(b []byte) [6]byte {
	var m [6]byte
	copy(m[:], b)
	return m
}
