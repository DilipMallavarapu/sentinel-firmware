// Command elfscan is a Sentinel Go worker.
//
// It walks an extracted firmware rootfs and reports, for every ELF it finds,
// the exploit-mitigation posture and the set of risky libc imports. A mid
// sized router image has 2,000-8,000 ELF objects and an OpenBMC or Hikvision
// image runs higher; doing this in Python takes minutes, doing it here with a
// bounded worker pool takes seconds, which is the whole reason the Go lane
// exists.
//
// Contract with the Python side (sentinel.core.goworker):
//   stdin   one JSON request object
//   stdout  newline-delimited JSON, one record per line, then a final
//           {"_done": true, ...} summary record
//   stderr  human-readable diagnostics only; never parsed
//   exit 0  even when findings exist; non-zero only on a harness error
//
// Every record is a *presence* fact about a file on disk. Nothing here claims
// exploitability -- "no stack canary" is a hardening gap, not a vulnerability,
// and the Python side is responsible for keeping that distinction in the
// finding text.
package main

import (
	"bufio"
	"crypto/sha256"
	"debug/elf"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

type Request struct {
	Root        string   `json:"root"`
	MaxFileSize int64    `json:"max_file_size"`
	Workers     int      `json:"workers"`
	SkipGlobs   []string `json:"skip_globs"`
}

type Mitigations struct {
	NX          bool   `json:"nx"`
	PIE         bool   `json:"pie"`
	RELRO       string `json:"relro"` // "none" | "partial" | "full"
	Canary      bool   `json:"canary"`
	Fortify     bool   `json:"fortify"`
	Stripped    bool   `json:"stripped"`
	RPath       string `json:"rpath,omitempty"`
	RunPath     string `json:"runpath,omitempty"`
	TextRelocs  bool   `json:"text_relocs"`
}

type Record struct {
	Path        string      `json:"path"`   // rootfs-relative
	SHA256      string      `json:"sha256"`
	Size        int64       `json:"size"`
	Arch        string      `json:"arch"`
	Type        string      `json:"type"`
	Interp      string      `json:"interp,omitempty"`
	Mitigations *Mitigations `json:"mitigations,omitempty"`
	RiskyIn     []string    `json:"risky_imports,omitempty"`
	NeedLibs    []string    `json:"needed,omitempty"`
	SetUID      bool        `json:"setuid"`
	Err         string      `json:"error,omitempty"`
}

type Summary struct {
	Done     bool    `json:"_done"`
	Scanned  int     `json:"scanned"`
	ELFs     int     `json:"elfs"`
	Errors   int     `json:"errors"`
	Seconds  float64 `json:"seconds"`
}

// Imports worth flagging. Kept deliberately short: a list that flags every
// libc call produces noise that trains the operator to ignore the column.
var riskyImports = map[string]string{
	"system":       "command execution",
	"popen":        "command execution",
	"execl":        "command execution",
	"execlp":       "command execution",
	"execve":       "command execution",
	"strcpy":       "unbounded copy",
	"strcat":       "unbounded concat",
	"sprintf":      "unbounded format",
	"vsprintf":     "unbounded format",
	"gets":         "unbounded read",
	"memcpy":       "", // tracked but not reported alone; too common
	"mkstemp":      "",
	"tmpnam":       "insecure temp file",
	"rand":         "weak randomness",
	"srand":        "weak randomness",
	"MD5_Init":     "weak hash",
	"DES_crypt":    "weak cipher",
}

func main() {
	var req Request
	dec := json.NewDecoder(os.Stdin)
	if err := dec.Decode(&req); err != nil && err != io.EOF {
		fmt.Fprintf(os.Stderr, "elfscan: bad request: %v\n", err)
		os.Exit(2)
	}
	if req.Root == "" {
		fmt.Fprintln(os.Stderr, "elfscan: root is required")
		os.Exit(2)
	}
	if req.Workers <= 0 {
		req.Workers = runtime.NumCPU()
	}
	if req.MaxFileSize <= 0 {
		req.MaxFileSize = 64 << 20
	}

	start := time.Now()
	out := bufio.NewWriterSize(os.Stdout, 1<<20)
	defer out.Flush()

	paths := make(chan string, 1024)
	records := make(chan Record, 1024)

	var wg sync.WaitGroup
	for i := 0; i < req.Workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for p := range paths {
				if rec, ok := inspect(req.Root, p); ok {
					records <- rec
				}
			}
		}()
	}

	var scanned, elfs, errs int
	var writeWG sync.WaitGroup
	writeWG.Add(1)
	enc := json.NewEncoder(out)
	go func() {
		defer writeWG.Done()
		for rec := range records {
			elfs++
			if rec.Err != "" {
				errs++
			}
			_ = enc.Encode(rec)
		}
	}()

	_ = filepath.WalkDir(req.Root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			return nil
		}
		if !d.Type().IsRegular() {
			return nil // never follow symlinks out of the extraction root
		}
		info, err := d.Info()
		if err != nil || info.Size() > req.MaxFileSize || info.Size() < 52 {
			return nil
		}
		for _, g := range req.SkipGlobs {
			if ok, _ := filepath.Match(g, filepath.Base(p)); ok {
				return nil
			}
		}
		scanned++
		paths <- p
		return nil
	})

	close(paths)
	wg.Wait()
	close(records)
	writeWG.Wait()

	_ = enc.Encode(Summary{
		Done: true, Scanned: scanned, ELFs: elfs, Errors: errs,
		Seconds: time.Since(start).Seconds(),
	})
}

func inspect(root, path string) (Record, bool) {
	fh, err := os.Open(path)
	if err != nil {
		return Record{}, false
	}
	defer fh.Close()

	var magic [4]byte
	if _, err := io.ReadFull(fh, magic[:]); err != nil {
		return Record{}, false
	}
	if magic != [4]byte{0x7f, 'E', 'L', 'F'} {
		return Record{}, false
	}
	if _, err := fh.Seek(0, io.SeekStart); err != nil {
		return Record{}, false
	}

	rel, _ := filepath.Rel(root, path)
	rec := Record{Path: filepath.ToSlash(rel)}

	if st, err := fh.Stat(); err == nil {
		rec.Size = st.Size()
		rec.SetUID = st.Mode()&os.ModeSetuid != 0
	}

	h := sha256.New()
	if _, err := io.Copy(h, fh); err == nil {
		rec.SHA256 = hex.EncodeToString(h.Sum(nil))
	}
	if _, err := fh.Seek(0, io.SeekStart); err != nil {
		return rec, true
	}

	f, err := elf.NewFile(fh)
	if err != nil {
		rec.Err = "elf parse: " + err.Error()
		return rec, true
	}
	defer f.Close()

	rec.Arch = f.Machine.String()
	rec.Type = f.Type.String()
	m := mitigations(f)
	rec.Mitigations = &m
	rec.Interp = interp(f)

	if libs, err := f.ImportedLibraries(); err == nil {
		rec.NeedLibs = libs
	}
	rec.RiskyIn = riskyIn(f)
	if s, err := f.DynString(elf.DT_RPATH); err == nil && len(s) > 0 {
		rec.Mitigations.RPath = strings.Join(s, ":")
	}
	if s, err := f.DynString(elf.DT_RUNPATH); err == nil && len(s) > 0 {
		rec.Mitigations.RunPath = strings.Join(s, ":")
	}
	return rec, true
}

func mitigations(f *elf.File) Mitigations {
	m := Mitigations{NX: true, RELRO: "none", Stripped: true}

	var hasRelroSeg, bindNow bool
	for _, p := range f.Progs {
		switch p.Type {
		case elf.PT_GNU_STACK:
			m.NX = p.Flags&elf.PF_X == 0
		case elf.PT_GNU_RELRO:
			hasRelroSeg = true
		}
	}
	if flags, err := f.DynValue(elf.DT_FLAGS); err == nil {
		for _, v := range flags {
			if elf.DynFlag(v)&elf.DF_BIND_NOW != 0 {
				bindNow = true
			}
		}
	}
	// DT_FLAGS_1 carries the underscore in debug/elf, and the DF_1_* bit
	// constants only arrived in a recent Go. Test the bit directly so this
	// builds against whatever toolchain is present: DF_1_NOW is 0x1 and has
	// been since the ABI was written.
	if flags1, err := f.DynValue(elf.DT_FLAGS_1); err == nil {
		for _, v := range flags1 {
			if v&0x1 != 0 { // DF_1_NOW
				bindNow = true
			}
		}
	}
	if _, err := f.DynValue(elf.DT_BIND_NOW); err == nil {
		bindNow = true
	}
	if hasRelroSeg {
		if bindNow {
			m.RELRO = "full"
		} else {
			m.RELRO = "partial"
		}
	}

	// ET_DYN with an interpreter is a PIE; ET_DYN without one is a shared
	// library, which is position independent by construction and should not
	// be reported as "PIE enabled" as though it were a hardening choice.
	m.PIE = f.Type == elf.ET_DYN && interp(f) != ""

	for _, s := range f.Sections {
		if s.Type == elf.SHT_SYMTAB {
			m.Stripped = false
		}
		if s.Name == ".text" && s.Flags&elf.SHF_WRITE != 0 {
			m.TextRelocs = true
		}
	}

	names := allSymbolNames(f)
	for _, n := range names {
		base := strings.TrimSuffix(strings.TrimPrefix(n, "__"), "@GLIBC_2.4")
		if strings.HasPrefix(base, "stack_chk_fail") {
			m.Canary = true
		}
		if strings.HasSuffix(base, "_chk") {
			m.Fortify = true
		}
	}
	return m
}

func interp(f *elf.File) string {
	for _, p := range f.Progs {
		if p.Type != elf.PT_INTERP {
			continue
		}
		buf := make([]byte, p.Filesz)
		if _, err := p.ReadAt(buf, 0); err == nil {
			return strings.TrimRight(string(buf), "\x00")
		}
	}
	return ""
}

func allSymbolNames(f *elf.File) []string {
	var out []string
	if syms, err := f.DynamicSymbols(); err == nil {
		for _, s := range syms {
			out = append(out, s.Name)
		}
	}
	if syms, err := f.Symbols(); err == nil {
		for _, s := range syms {
			out = append(out, s.Name)
		}
	}
	return out
}

func riskyIn(f *elf.File) []string {
	seen := map[string]bool{}
	var out []string
	syms, err := f.ImportedSymbols()
	if err != nil {
		return nil
	}
	for _, s := range syms {
		name := strings.SplitN(s.Name, "@", 2)[0]
		reason, ok := riskyImports[name]
		if !ok || reason == "" || seen[name] {
			continue
		}
		seen[name] = true
		out = append(out, name+": "+reason)
	}
	return out
}
