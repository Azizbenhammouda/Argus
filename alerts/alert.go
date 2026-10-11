package alerts

import (
	"fmt"
	"io"
	"log"
	"os"
	"time"
)

type Event struct {
	Rule    string
	SrcIP   string
	DstIP   string
	SrcPort string
	DstPort string
	Detail  string
}

type Alerter struct {
	logger *log.Logger
	file   *os.File
}

func New(path string) *Alerter {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Printf("warning: could not open alert log %q: %v (stdout only)\n", path, err)
		return &Alerter{logger: log.New(os.Stdout, "", 0)}
	}

	mw := io.MultiWriter(os.Stdout, f)
	return &Alerter{
		logger: log.New(mw, "", 0),
		file:   f,
	}
}

func (a *Alerter) Fire(e Event) {
	ts := time.Now().Format("2006-01-02 15:04:05")
	if e.SrcPort != "" || e.DstPort != "" {
		a.logger.Printf("[%s] ALERT %-14s src=%s:%s dst=%s:%s — %s",
			ts, e.Rule, e.SrcIP, e.SrcPort, e.DstIP, e.DstPort, e.Detail)
		return
	}
	a.logger.Printf("[%s] ALERT %-14s src=%s — %s",
		ts, e.Rule, e.SrcIP, e.Detail)
}

func (a *Alerter) Close() {
	if a.file != nil {
		a.file.Close()
	}
}
