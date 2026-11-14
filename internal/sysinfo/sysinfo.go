package sysinfo

import (
	"devdoctor/internal/sh"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Disk struct {
	Mount    string  `json:"mount"`
	FS       string  `json:"fs"`
	Type     string  `json:"type"`
	Total    uint64  `json:"total"`
	Used     uint64  `json:"used"`
	Pct      float64 `json:"pct"`
	InodePct float64 `json:"inode_pct"`
}
type Proc struct {
	PID  int     `json:"pid"`
	User string  `json:"user"`
	CPU  float64 `json:"cpu"`
	Mem  float64 `json:"mem"`
	Cmd  string  `json:"cmd"`
}
type History struct {
	CPU []float64 `json:"cpu"`
	Mem []float64 `json:"mem"`
	Rx  []float64 `json:"rx"`
	Tx  []float64 `json:"tx"`
}
type Snapshot struct {
	Host      string     `json:"host"`
	OS        string     `json:"os"`
	Kernel    string     `json:"kernel"`
	CPUModel  string     `json:"cpu_model"`
	Cores     int        `json:"cores"`
	UptimeSec float64    `json:"uptime_sec"`
	Load      [3]float64 `json:"load"`
	CPU       float64    `json:"cpu"`
	MemTotal  uint64     `json:"mem_total"`
	MemUsed   uint64     `json:"mem_used"`
	SwapTotal uint64     `json:"swap_total"`
	SwapUsed  uint64     `json:"swap_used"`
	Rx        float64    `json:"rx"`
	Tx        float64    `json:"tx"`
	Disks     []Disk     `json:"disks"`
	Procs     []Proc     `json:"procs"`
	Zombies   int        `json:"zombies"`
	IPs       []string   `json:"ips"`
	History   History    `json:"history"`
	Time      time.Time  `json:"time"`
}

type Sampler struct {
	mu   sync.RWMutex
	snap Snapshot
	hist History

	prevIdle, prevTotal uint64
	prevRx, prevTx      uint64
	prevT               time.Time
}

const histLen = 90

func push(s []float64, v float64) []float64 {
	s = append(s, v)
	if len(s) > histLen {
		s = s[len(s)-histLen:]
	}
	return s
}

func (s *Sampler) Start() {
	s.static()
	s.tick(0)
	go func() {
		t := time.NewTicker(2 * time.Second)
		for i := 1; ; i++ {
			<-t.C
			s.tick(i)
		}
	}()
}

func (s *Sampler) Get() Snapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sn := s.snap
	sn.History = History{
		CPU: append([]float64(nil), s.hist.CPU...), Mem: append([]float64(nil), s.hist.Mem...),
		Rx: append([]float64(nil), s.hist.Rx...), Tx: append([]float64(nil), s.hist.Tx...),
	}
	return sn
}

func (s *Sampler) static() {
	sn := &s.snap
	sn.Host, _ = os.Hostname()
	sn.OS = "Linux"
	for _, l := range strings.Split(sh.ReadFile("/etc/os-release"), "\n") {
		if strings.HasPrefix(l, "PRETTY_NAME=") {
			sn.OS = strings.Trim(strings.TrimPrefix(l, "PRETTY_NAME="), `"`)
		}
	}
	sn.Kernel = strings.TrimSpace(sh.ReadFile("/proc/sys/kernel/osrelease"))
	for _, l := range strings.Split(sh.ReadFile("/proc/cpuinfo"), "\n") {
		if strings.HasPrefix(l, "processor") {
			sn.Cores++
		} else if strings.HasPrefix(l, "model name") && sn.CPUModel == "" {
			if i := strings.Index(l, ":"); i > 0 {
				sn.CPUModel = strings.TrimSpace(l[i+1:])
			}
		}
	}
}

func (s *Sampler) tick(i int) {
	cpu := s.readCPU()
	mt, mu, st, su := readMem()
	rx, tx := s.readNet()
	var load [3]float64
	if f := strings.Fields(sh.ReadFile("/proc/loadavg")); len(f) >= 3 {
		for k := 0; k < 3; k++ {
			load[k], _ = strconv.ParseFloat(f[k], 64)
		}
	}
	var up float64
	if f := strings.Fields(sh.ReadFile("/proc/uptime")); len(f) > 0 {
		up, _ = strconv.ParseFloat(f[0], 64)
	}
	var disks []Disk
	var procs []Proc
	var zombies int
	if i%15 == 0 {
		disks = readDisks()
	}
	if i%3 == 0 {
		procs, zombies = readProcs()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	sn := &s.snap
	sn.CPU, sn.MemTotal, sn.MemUsed, sn.SwapTotal, sn.SwapUsed = cpu, mt, mu, st, su
	sn.Rx, sn.Tx, sn.Load, sn.UptimeSec, sn.Time = rx, tx, load, up, time.Now()
	if disks != nil {
		sn.Disks = disks
		sn.IPs = localIPs()
	}
	if procs != nil {
		sn.Procs, sn.Zombies = procs, zombies
	}
	mp := 0.0
	if mt > 0 {
		mp = float64(mu) / float64(mt) * 100
	}
	s.hist.CPU, s.hist.Mem = push(s.hist.CPU, cpu), push(s.hist.Mem, mp)
	s.hist.Rx, s.hist.Tx = push(s.hist.Rx, rx), push(s.hist.Tx, tx)
}

func (s *Sampler) readCPU() float64 {
	l := strings.SplitN(sh.ReadFile("/proc/stat"), "\n", 2)[0]
	f := strings.Fields(l)
	if len(f) < 8 || f[0] != "cpu" {
		return 0
	}
	var total, idle uint64
	for i := 1; i < len(f) && i <= 8; i++ {
		v, _ := strconv.ParseUint(f[i], 10, 64)
		total += v
		if i == 4 || i == 5 {
			idle += v
		}
	}
	dt, di := total-s.prevTotal, idle-s.prevIdle
	first := s.prevTotal == 0
	s.prevTotal, s.prevIdle = total, idle
	if first || dt == 0 {
		return 0
	}
	return float64(dt-di) / float64(dt) * 100
}

func readMem() (total, used, swapT, swapU uint64) {
	m := map[string]uint64{}
	for _, l := range strings.Split(sh.ReadFile("/proc/meminfo"), "\n") {
		f := strings.Fields(l)
		if len(f) >= 2 {
			v, _ := strconv.ParseUint(f[1], 10, 64)
			m[strings.TrimSuffix(f[0], ":")] = v * 1024
		}
	}
	total = m["MemTotal"]
	avail, ok := m["MemAvailable"]
	if !ok {
		avail = m["MemFree"] + m["Buffers"] + m["Cached"]
	}
	if total > avail {
		used = total - avail
	}
	swapT = m["SwapTotal"]
	if swapT > m["SwapFree"] {
		swapU = swapT - m["SwapFree"]
	}
	return
}

func (s *Sampler) readNet() (rx, tx float64) {
	var r, t uint64
	for _, l := range strings.Split(sh.ReadFile("/proc/net/dev"), "\n") {
		i := strings.Index(l, ":")
		if i < 0 {
			continue
		}
		name := strings.TrimSpace(l[:i])
		if name == "lo" || strings.HasPrefix(name, "veth") || strings.HasPrefix(name, "docker") || strings.HasPrefix(name, "br-") {
			continue
		}
		f := strings.Fields(l[i+1:])
		if len(f) >= 9 {
			a, _ := strconv.ParseUint(f[0], 10, 64)
			b, _ := strconv.ParseUint(f[8], 10, 64)
			r, t = r+a, t+b
		}
	}
	now := time.Now()
	if !s.prevT.IsZero() && r >= s.prevRx && t >= s.prevTx {
		dt := now.Sub(s.prevT).Seconds()
		if dt > 0 {
			rx, tx = float64(r-s.prevRx)/dt, float64(t-s.prevTx)/dt
		}
	}
	s.prevRx, s.prevTx, s.prevT = r, t, now
	return
}

func readDisks() []Disk {
	out, err := sh.Run(8*time.Second, "df", "-PT", "-B1", "-x", "tmpfs", "-x", "devtmpfs", "-x", "squashfs", "-x", "overlay", "-x", "efivarfs")
	if err != nil && out == "" {
		return nil
	}
	inodes := map[string]float64{}
	if io, _ := sh.Run(8*time.Second, "df", "-Pi", "-x", "tmpfs", "-x", "devtmpfs", "-x", "squashfs", "-x", "overlay"); io != "" {
		lines := strings.Split(io, "\n")
		for _, l := range lines[1:] {
			f := strings.Fields(l)
			if len(f) >= 6 {
				p, _ := strconv.ParseFloat(strings.TrimSuffix(f[4], "%"), 64)
				inodes[f[5]] = p
			}
		}
	}
	var ds []Disk
	lines := strings.Split(out, "\n")
	for _, l := range lines[1:] {
		f := strings.Fields(l)
		if len(f) < 7 {
			continue
		}
		t, _ := strconv.ParseUint(f[2], 10, 64)
		u, _ := strconv.ParseUint(f[3], 10, 64)
		if t == 0 {
			continue
		}
		ds = append(ds, Disk{Mount: f[6], FS: f[0], Type: f[1], Total: t, Used: u,
			Pct: float64(u) / float64(t) * 100, InodePct: inodes[f[6]]})
	}
	return ds
}

func readProcs() ([]Proc, int) {
	out, err := sh.Run(5*time.Second, "ps", "-eo", "pid=,user=,stat=,pcpu=,pmem=,comm=", "--sort=-pcpu")
	if err != nil && out == "" {
		return nil, 0
	}
	var ps []Proc
	z := 0
	for _, l := range strings.Split(out, "\n") {
		f := strings.Fields(l)
		if len(f) < 6 {
			continue
		}
		if strings.HasPrefix(f[2], "Z") {
			z++
		}
		if len(ps) < 8 {
			pid, _ := strconv.Atoi(f[0])
			c, _ := strconv.ParseFloat(f[3], 64)
			m, _ := strconv.ParseFloat(f[4], 64)
			ps = append(ps, Proc{pid, f[1], c, m, strings.Join(f[5:], " ")})
		}
	}
	return ps, z
}

func localIPs() []string {
	var ips []string
	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok && !n.IP.IsLoopback() && n.IP.To4() != nil {
			ips = append(ips, n.IP.String())
		}
	}
	return ips
}

// PrimaryIP devuelve la IP de salida por defecto (no envía tráfico).
func PrimaryIP() string {
	if c, err := net.Dial("udp", "192.0.2.1:9"); err == nil {
		defer c.Close()
		if a, ok := c.LocalAddr().(*net.UDPAddr); ok {
			return a.IP.String()
		}
	}
	if ips := localIPs(); len(ips) > 0 {
		return ips[0]
	}
	return "127.0.0.1"
}
