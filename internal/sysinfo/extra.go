package sysinfo

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"devdoctor/internal/sh"
)

// CPUBreak reparte el uso de CPU (porcentaje del total) entre sus causas.
type CPUBreak struct {
	User   float64 `json:"user"`
	System float64 `json:"system"`
	IOWait float64 `json:"iowait"`
	Steal  float64 `json:"steal"`
}

// Conns cuenta sockets TCP por estado.
type Conns struct {
	Established int `json:"established"`
	TimeWait    int `json:"time_wait"`
	Listen      int `json:"listen"`
}

// Tasks resume los procesos del sistema.
type Tasks struct {
	Processes int `json:"processes"`
	Threads   int `json:"threads"`
	Running   int `json:"running"`
}

type extraState struct {
	prevDisk  [4]uint64 // lecturas, sectores leídos, escrituras, sectores escritos
	prevDiskT time.Time
	prevPk    [2]uint64 // paquetes rx, tx
	prevPkT   time.Time
}

type extra struct {
	DiskRead, DiskWrite, DiskIOPS float64
	RxPkts, TxPkts                float64
	NetErrs                       uint64
	Conns                         Conns
	Tasks                         Tasks
	TempC                         float64
	slow                          bool // true cuando se han refrescado las métricas costosas
}

var diskDev = regexp.MustCompile(`^(sd[a-z]+|vd[a-z]+|xvd[a-z]+|hd[a-z]+|nvme\d+n\d+|mmcblk\d+)$`)

func u64(s string) uint64 { v, _ := strconv.ParseUint(s, 10, 64); return v }

func (s *Sampler) sampleExtra(i int) extra {
	var e extra
	now := time.Now()

	// --- E/S de disco (dispositivos físicos; las particiones no se suman dos veces) ---
	var rd, sr, wr, sw uint64
	for _, l := range strings.Split(sh.ReadFile("/proc/diskstats"), "\n") {
		f := strings.Fields(l)
		if len(f) < 10 || !diskDev.MatchString(f[2]) {
			continue
		}
		rd, sr, wr, sw = rd+u64(f[3]), sr+u64(f[5]), wr+u64(f[7]), sw+u64(f[9])
	}
	if p := s.exs.prevDisk; !s.exs.prevDiskT.IsZero() && sr >= p[1] && sw >= p[3] {
		if dt := now.Sub(s.exs.prevDiskT).Seconds(); dt > 0 {
			e.DiskRead = float64(sr-p[1]) * 512 / dt
			e.DiskWrite = float64(sw-p[3]) * 512 / dt
			e.DiskIOPS = float64((rd-p[0])+(wr-p[2])) / dt
		}
	}
	s.exs.prevDisk, s.exs.prevDiskT = [4]uint64{rd, sr, wr, sw}, now

	// --- paquetes y errores de red ---
	var rp, tp uint64
	for _, l := range strings.Split(sh.ReadFile("/proc/net/dev"), "\n") {
		k := strings.Index(l, ":")
		if k < 0 {
			continue
		}
		n := strings.TrimSpace(l[:k])
		if n == "lo" || strings.HasPrefix(n, "veth") || strings.HasPrefix(n, "docker") || strings.HasPrefix(n, "br-") {
			continue
		}
		f := strings.Fields(l[k+1:])
		if len(f) >= 12 {
			rp, tp = rp+u64(f[1]), tp+u64(f[9])
			e.NetErrs += u64(f[2]) + u64(f[3]) + u64(f[10]) + u64(f[11])
		}
	}
	if !s.exs.prevPkT.IsZero() && rp >= s.exs.prevPk[0] && tp >= s.exs.prevPk[1] {
		if dt := now.Sub(s.exs.prevPkT).Seconds(); dt > 0 {
			e.RxPkts, e.TxPkts = float64(rp-s.exs.prevPk[0])/dt, float64(tp-s.exs.prevPk[1])/dt
		}
	}
	s.exs.prevPk, s.exs.prevPkT = [2]uint64{rp, tp}, now

	if i%3 != 0 {
		return e
	}
	e.slow = true

	// --- conexiones TCP ---
	for _, p := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		lines := strings.Split(sh.ReadFile(p), "\n")
		for k := 1; k < len(lines); k++ {
			f := strings.Fields(lines[k])
			if len(f) < 4 {
				continue
			}
			switch f[3] {
			case "01":
				e.Conns.Established++
			case "06":
				e.Conns.TimeWait++
			case "0A":
				e.Conns.Listen++
			}
		}
	}

	// --- procesos, hilos y ejecutándose ---
	if f := strings.Fields(sh.ReadFile("/proc/loadavg")); len(f) >= 4 {
		if rt := strings.Split(f[3], "/"); len(rt) == 2 {
			e.Tasks.Running, _ = strconv.Atoi(rt[0])
			e.Tasks.Threads, _ = strconv.Atoi(rt[1])
		}
	}
	if ents, err := os.ReadDir("/proc"); err == nil {
		for _, d := range ents {
			if d.IsDir() {
				if c := d.Name()[0]; c >= '1' && c <= '9' {
					e.Tasks.Processes++
				}
			}
		}
	}

	// --- temperatura (la zona más caliente) ---
	if zs, _ := filepath.Glob("/sys/class/thermal/thermal_zone*/temp"); zs != nil {
		for _, z := range zs {
			if v, err := strconv.ParseFloat(strings.TrimSpace(sh.ReadFile(z)), 64); err == nil {
				if c := v / 1000; c > 1 && c < 130 && c > e.TempC {
					e.TempC = c
				}
			}
		}
	}

	return e
}
