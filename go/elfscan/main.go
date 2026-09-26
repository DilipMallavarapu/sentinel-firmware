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

// State is the three-valued result of a symbol-derived mitigation check.
// A missing symbol table means "we could not look", which is *unknown*, not
// *absent*: reporting unknown as absent is the specific lie this worker used
// to tell on sstripped images, and the reason the aggregate later read 0/54
// when the true figure was the opposite.
type State string

const (
	Present State = "present"
	Absent  State = "absent"
	Unknown State = "unknown"
)

type Mitigations struct {
	NX         bool   `json:"nx"`  // phdr-derived: always determinable
	PIE        bool   `json:"pie"` // phdr-derived: always determinable
	RELRO      string `json:"relro"` // "none" | "partial" | "full"
	Canary     State  `json:"canary"`  // symbol-derived: present|absent|unknown
	Fortify    State  `json:"fortify"` // symbol-derived: present|absent|unknown
	Stripped   bool   `json:"stripped"`
	RPath      string `json:"rpath,omitempty"`
	RunPath    string `json:"runpath,omitempty"`
	TextRelocs bool   `json:"text_relocs"`
}

// SymEvidence records *how* the canary/fortify verdict was reached and where
// the searched bytes live, so the Python side can build a proof artifact that
// re-derives the verdict offline rather than re-proving the ELF header (which
// says nothing about symbols). All offsets are absolute file offsets.
type SymEvidence struct {
	Source    string `json:"source"`               // "dynamic-strtab" | "symtab-section" | "none"
	StrtabOff int64  `json:"strtab_off,omitempty"` // start of the region searched
	StrtabLen int64  `json:"strtab_len,omitempty"` // length of the region searched
	CanaryOff int64  `json:"canary_off,omitempty"` // file offset of the matched token, when present
	Reason    string `json:"reason,omitempty"`     // why the verdict is unknown
}

type Record struct {
	Path        string      `json:"path"`   // rootfs-relative
	SHA256      string      `json:"sha256"`
	Size        int64       `json:"size"`
	Arch        string      `json:"arch"`
	Type        string      `json:"type"`
	Interp      string      `json:"interp,omitempty"`
	Mitigations *Mitigations `json:"mitigations,omitempty"`
	SymEv       *SymEvidence `json:"sym_evidence,omitempty"`
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
	// Canary/fortify are symbol-derived and must survive section stripping;
	// scanSymbols reads the dynamic string table straight from PT_DYNAMIC so
	// an sstripped binary yields a real verdict, not a false "absent".
	ev := scanSymbols(f)
	m.Canary, m.Fortify = ev.canary, ev.fortify
	rec.Mitigations = &m
	rec.SymEv = &SymEvidence{
		Source:    ev.source,
		StrtabOff: ev.regionOff,
		StrtabLen: ev.regionLen,
		CanaryOff: ev.canaryOff,
		Reason:    ev.reason,
	}
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

	// Canary/fortify are filled in by scanSymbols at the call site; they are
	// left at their zero value ("") here so a caller that forgets is visibly
	// wrong rather than silently reporting a false "absent".
	return m
}

// symResult carries the tri-state verdicts plus enough provenance for the
// Python side to persist a re-derivable proof.
type symResult struct {
	canary    State
	fortify   State
	source    string
	reason    string
	regionOff int64 // absolute file offset of the searched byte region
	regionLen int64
	canaryOff int64 // absolute file offset of the matched canary token, if present
}

// scanSymbols decides canary/fortify presence from symbol *names*, the same
// signal checksec uses. The name of an imported function is only present in a
// binary's string table if a relocation references it, so "__stack_chk_fail"
// in .dynstr means at least one function was compiled with -fstack-protector.
//
// The key difference from the old code: it reads .dynstr directly from the
// PT_DYNAMIC segment (DT_STRTAB/DT_STRSZ), which survives `sstrip`. Only when
// there is no dynamic string table *and* no section symbol table do we admit
// we cannot tell and return Unknown with a reason.
func scanSymbols(f *elf.File) symResult {
	// Primary: the dynamic string table, read from the segment not the
	// (possibly stripped) sections. This is the path that fixes OpenWrt.
	if region, off, ok := dynStrTab(f); ok {
		r := symResult{
			source: "dynamic-strtab", regionOff: off, regionLen: int64(len(region)),
			canary: Absent, fortify: Absent,
		}
		scanTokens(region, off, &r)
		return r
	}

	// Fallback: a statically linked binary that still has a .symtab section
	// (i.e. not stripped) can be read through debug/elf. The searched region
	// is synthesized from the names, so the proof is derived-not-raw; that is
	// noted in the source string and is still deterministic offline.
	if names := allSymbolNames(f); len(names) > 0 {
		region := []byte(strings.Join(names, "\x00") + "\x00")
		r := symResult{
			source: "symtab-section", regionOff: 0, regionLen: int64(len(region)),
			canary: Absent, fortify: Absent,
		}
		scanTokens(region, 0, &r)
		return r
	}

	// Neither source exists: statically linked and stripped, or a symbol
	// table we could not locate. This is genuinely unknown -- the honest
	// verdict the old code refused to give.
	return symResult{
		canary: Unknown, fortify: Unknown, source: "none",
		reason: "no dynamic string table (DT_STRTAB) and no symbol section; " +
			"symbol-derived mitigations are unmeasurable for this binary",
	}
}

// scanTokens splits a NUL-delimited string table and applies the canary /
// fortify name tests to each token, recording the file offset of the canary
// token so the proof can point straight at it.
func scanTokens(region []byte, regionOff int64, r *symResult) {
	pos := 0
	for pos < len(region) {
		end := pos
		for end < len(region) && region[end] != 0 {
			end++
		}
		if end > pos {
			tok := string(region[pos:end])
			base := strings.TrimSuffix(strings.TrimPrefix(tok, "__"), "@GLIBC_2.4")
			if strings.HasPrefix(base, "stack_chk") {
				r.canary = Present
				r.canaryOff = regionOff + int64(pos)
			}
			if strings.HasSuffix(base, "_chk") {
				r.fortify = Present
			}
		}
		pos = end + 1
	}
}

// dynStrTab returns the .dynstr bytes and their absolute file offset, read
// from the PT_DYNAMIC segment so it does not depend on section headers.
// Returns ok=false when there is no dynamic segment or it does not describe a
// string table that lands inside a loadable segment.
func dynStrTab(f *elf.File) (region []byte, fileOff int64, ok bool) {
	var dyn *elf.Prog
	for _, p := range f.Progs {
		if p.Type == elf.PT_DYNAMIC {
			dyn = p
			break
		}
	}
	if dyn == nil || dyn.Filesz == 0 || dyn.Filesz > (16<<20) {
		return nil, 0, false
	}
	raw := make([]byte, dyn.Filesz)
	if _, err := dyn.ReadAt(raw, 0); err != nil {
		return nil, 0, false
	}

	bo := f.ByteOrder
	var strtabVA, strsz uint64
	var haveStr bool
	if f.Class == elf.ELFCLASS32 {
		for i := 0; i+8 <= len(raw); i += 8 {
			tag := elf.DynTag(int32(bo.Uint32(raw[i:])))
			val := uint64(bo.Uint32(raw[i+4:]))
			switch tag {
			case elf.DT_STRTAB:
				strtabVA, haveStr = val, true
			case elf.DT_STRSZ:
				strsz = val
			case elf.DT_NULL:
				i = len(raw) // stop
			}
		}
	} else {
		for i := 0; i+16 <= len(raw); i += 16 {
			tag := elf.DynTag(int64(bo.Uint64(raw[i:])))
			val := bo.Uint64(raw[i+8:])
			switch tag {
			case elf.DT_STRTAB:
				strtabVA, haveStr = val, true
			case elf.DT_STRSZ:
				strsz = val
			case elf.DT_NULL:
				i = len(raw)
			}
		}
	}
	if !haveStr || strsz == 0 || strsz > (64<<20) {
		return nil, 0, false
	}

	// DT_STRTAB is a virtual address; map it back to a file offset through the
	// loadable segment that contains it.
	for _, p := range f.Progs {
		if p.Type != elf.PT_LOAD {
			continue
		}
		if strtabVA >= p.Vaddr && strtabVA+strsz <= p.Vaddr+p.Filesz {
			buf := make([]byte, strsz)
			if _, err := p.ReadAt(buf, int64(strtabVA-p.Vaddr)); err != nil {
				return nil, 0, false
			}
			return buf, int64(p.Off) + int64(strtabVA-p.Vaddr), true
		}
	}
	return nil, 0, false
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
