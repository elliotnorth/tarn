// Package backup saves tarn's state directory to one archive and puts it back.
//
// The archive is a gzipped tar holding the state directory under "state/", the
// services file under "services" when it lives outside the state directory,
// and a small manifest. It holds the certificate keys and the ACME account key,
// so it is written owner-only. The Cloudflare token isn't in the state
// directory and isn't saved.
//
// Restore treats the archive as untrusted: no absolute paths, no "..", no
// links or devices, and size limits on every file and the whole archive. It
// extracts next to the state directory and swaps the result in, so a failed
// restore leaves the old state as it was.
package backup

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"
)

// Format is the archive layout version. Restore refuses any other.
const Format = 1

const (
	manifestName = "tarn-backup.json"
	stateRoot    = "state"
	servicesName = "services"

	maxFile  = 16 << 20 // no single state file is anywhere near this
	maxTotal = 64 << 20
	maxFiles = 10000
)

// Manifest describes an archive.
type Manifest struct {
	Format       int       `json:"format"`
	Created      time.Time `json:"created"`
	TarnVersion  string    `json:"tarn_version"`
	StateDir     string    `json:"state_dir"`
	ServicesFile string    `json:"services_file,omitempty"` // original path, when saved separately
}

// Create writes an archive of stateDir to w. servicesFile is saved too when it
// is set and outside stateDir. Symlinks inside the state directory are
// skipped: tarn never makes them.
func Create(w io.Writer, stateDir, servicesFile, tarnVersion string, now time.Time) (*Manifest, error) {
	real, err := filepath.EvalSymlinks(stateDir)
	if err != nil {
		return nil, fmt.Errorf("state directory: %w", err)
	}
	if fi, err := os.Stat(real); err != nil {
		return nil, fmt.Errorf("state directory: %w", err)
	} else if !fi.IsDir() {
		return nil, fmt.Errorf("state directory %s is not a directory", stateDir)
	}

	m := &Manifest{Format: Format, Created: now.UTC(), TarnVersion: tarnVersion, StateDir: stateDir}
	if servicesFile != "" && !inside(real, servicesFile) {
		m.ServicesFile = servicesFile
	}

	gz := gzip.NewWriter(w)
	tw := tar.NewWriter(gz)

	mb, _ := json.MarshalIndent(m, "", "  ")
	if err := writeEntry(tw, manifestName, 0o600, now, mb); err != nil {
		return nil, err
	}

	err = filepath.WalkDir(real, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(real, p)
		if err != nil {
			return err
		}
		name := path.Join(stateRoot, filepath.ToSlash(rel))
		switch {
		case d.IsDir():
			return tw.WriteHeader(&tar.Header{Typeflag: tar.TypeDir, Name: name + "/", Mode: 0o700, ModTime: now})
		case d.Type().IsRegular():
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			return writeEntry(tw, name, 0o600, now, b)
		default:
			return nil // symlinks, sockets: not tarn's
		}
	})
	if err != nil {
		return nil, fmt.Errorf("reading the state directory: %w", err)
	}

	if m.ServicesFile != "" {
		b, err := os.ReadFile(servicesFile)
		if err != nil {
			return nil, fmt.Errorf("services file: %w", err)
		}
		if err := writeEntry(tw, servicesName, 0o600, now, b); err != nil {
			return nil, err
		}
	}

	if err := tw.Close(); err != nil {
		return nil, err
	}
	return m, gz.Close()
}

func writeEntry(tw *tar.Writer, name string, mode int64, now time.Time, b []byte) error {
	if err := tw.WriteHeader(&tar.Header{Typeflag: tar.TypeReg, Name: name, Mode: mode, Size: int64(len(b)), ModTime: now}); err != nil {
		return err
	}
	_, err := tw.Write(b)
	return err
}

// inside reports whether p is within dir, after resolving what can be resolved.
func inside(dir, p string) bool {
	if r, err := filepath.EvalSymlinks(p); err == nil {
		p = r
	}
	rel, err := filepath.Rel(dir, p)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel)
}

// RestoreResult says what Restore did.
type RestoreResult struct {
	Manifest *Manifest
	Previous string // where the old state directory was moved; empty if there was none
	Services string // where the services file was written; empty if it wasn't
	// ServicesSkipped is the requested services path when a file was already
	// there and was left alone. The saved copy is in the state directory.
	ServicesSkipped string
}

// Restore replaces stateDir with the archive in r. The current state, if any,
// is kept as a sibling named <dir>.before-restore-<time>.
//
// A saved services file is written to servicesDst, which comes from the person
// running the restore and never from the archive: a crafted archive must not
// choose where root writes. It is written only if nothing is there yet. With
// no servicesDst, or when the file exists, it goes into the restored state
// directory as restored-services.
//
// The caller must make sure tarn isn't running.
func Restore(r io.Reader, stateDir, servicesDst string, now time.Time) (*RestoreResult, error) {
	real, err := resolveTarget(stateDir)
	if err != nil {
		return nil, err
	}
	parent := filepath.Dir(real)
	stamp := now.UTC().Format("20060102-150405")

	tmp, err := os.MkdirTemp(parent, "."+filepath.Base(real)+".restore-")
	if err != nil {
		return nil, fmt.Errorf("can't create a temporary directory next to %s: %w", real, err)
	}
	ok := false
	defer func() {
		if !ok {
			os.RemoveAll(tmp)
		}
	}()
	if err := os.Chmod(tmp, 0o700); err != nil {
		return nil, err
	}

	m, services, err := extract(r, tmp)
	if err != nil {
		return nil, err
	}

	res := &RestoreResult{Manifest: m}
	if services != nil {
		dst := servicesDst
		keep := func() error {
			return os.WriteFile(filepath.Join(tmp, "restored-services"), services, 0o600)
		}
		if dst == "" {
			if err := keep(); err != nil {
				return nil, err
			}
		} else if _, err := os.Lstat(dst); err == nil {
			res.ServicesSkipped = dst
			if err := keep(); err != nil {
				return nil, err
			}
		} else if errors.Is(err, fs.ErrNotExist) {
			// O_EXCL: never replace something that appeared meanwhile.
			f, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
			if err != nil {
				return nil, fmt.Errorf("services file: %w", err)
			}
			_, werr := f.Write(services)
			if cerr := f.Close(); werr == nil {
				werr = cerr
			}
			if werr != nil {
				return nil, fmt.Errorf("services file: %w", werr)
			}
			res.Services = dst
		} else {
			return nil, fmt.Errorf("services file: %w", err)
		}
	}

	if _, err := os.Lstat(real); err == nil {
		prev := real + ".before-restore-" + stamp
		if err := os.Rename(real, prev); err != nil {
			return nil, fmt.Errorf("can't move the current state aside: %w", err)
		}
		res.Previous = prev
		if err := os.Rename(tmp, real); err != nil {
			os.Rename(prev, real) // put it back
			return nil, fmt.Errorf("can't move the restored state into place: %w", err)
		}
	} else if errors.Is(err, fs.ErrNotExist) {
		if err := os.Rename(tmp, real); err != nil {
			return nil, fmt.Errorf("can't move the restored state into place: %w", err)
		}
	} else {
		return nil, err
	}
	ok = true
	return res, nil
}

// resolveTarget follows symlinks to the real state directory, so a systemd
// DynamicUser link (/var/lib/tarn -> private/tarn) stays a link. A missing
// directory is fine as long as its parent exists.
func resolveTarget(stateDir string) (string, error) {
	abs, err := filepath.Abs(stateDir)
	if err != nil {
		return "", err
	}
	if real, err := filepath.EvalSymlinks(abs); err == nil {
		if fi, err := os.Stat(real); err != nil || !fi.IsDir() {
			return "", fmt.Errorf("%s is not a directory", stateDir)
		}
		return real, nil
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(abs))
	if err != nil {
		return "", fmt.Errorf("the parent of %s doesn't exist", stateDir)
	}
	return filepath.Join(parent, filepath.Base(abs)), nil
}

// extract unpacks the archive into dir, which must be empty, and returns the
// manifest and the services file's contents, if any.
func extract(r io.Reader, dir string) (*Manifest, []byte, error) {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return nil, nil, errors.New("not a tarn backup (not gzip)")
	}
	tr := tar.NewReader(gz)

	var (
		m        *Manifest
		services []byte
		total    int64
		files    int
	)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, nil, fmt.Errorf("reading the archive: %w", err)
		}
		if files++; files > maxFiles {
			return nil, nil, errors.New("the archive has too many entries")
		}
		name := h.Name
		if name == "" || strings.Contains(name, "\\") || path.IsAbs(name) {
			return nil, nil, fmt.Errorf("unsafe path in the archive: %q", name)
		}
		clean := path.Clean(name)
		if clean == ".." || strings.HasPrefix(clean, "../") || clean != strings.TrimSuffix(name, "/") {
			return nil, nil, fmt.Errorf("unsafe path in the archive: %q", name)
		}

		switch h.Typeflag {
		case tar.TypeDir:
			rel, ok := underState(clean)
			if !ok {
				return nil, nil, fmt.Errorf("unexpected entry in the archive: %q", name)
			}
			if rel != "" {
				if err := os.MkdirAll(filepath.Join(dir, filepath.FromSlash(rel)), 0o700); err != nil {
					return nil, nil, err
				}
			}
			continue
		case tar.TypeReg:
		default:
			return nil, nil, fmt.Errorf("the archive holds a link or special file: %q", name)
		}

		if h.Size < 0 || h.Size > maxFile {
			return nil, nil, fmt.Errorf("%q is too large", name)
		}
		if total += h.Size; total > maxTotal {
			return nil, nil, errors.New("the archive is too large")
		}
		b, err := io.ReadAll(io.LimitReader(tr, h.Size))
		if err != nil {
			return nil, nil, fmt.Errorf("reading %q: %w", name, err)
		}

		switch {
		case clean == manifestName:
			var mm Manifest
			if err := json.Unmarshal(b, &mm); err != nil {
				return nil, nil, errors.New("the archive's manifest is unreadable")
			}
			if mm.Format != Format {
				return nil, nil, fmt.Errorf("backup format %d isn't supported by this tarn (it reads %d)", mm.Format, Format)
			}
			m = &mm
		case clean == servicesName:
			services = b
		default:
			rel, ok := underState(clean)
			if !ok || rel == "" {
				return nil, nil, fmt.Errorf("unexpected entry in the archive: %q", name)
			}
			dst := filepath.Join(dir, filepath.FromSlash(rel))
			if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
				return nil, nil, err
			}
			f, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
			if err != nil {
				return nil, nil, fmt.Errorf("writing %q: %w", rel, err)
			}
			_, werr := f.Write(b)
			if werr == nil {
				werr = f.Sync()
			}
			if cerr := f.Close(); werr == nil {
				werr = cerr
			}
			if werr != nil {
				return nil, nil, fmt.Errorf("writing %q: %w", rel, werr)
			}
		}
	}
	if m == nil {
		return nil, nil, errors.New("not a tarn backup (no manifest)")
	}
	if services != nil && m.ServicesFile == "" {
		return nil, nil, errors.New("the archive has a services file but no path for it")
	}
	return m, services, nil
}

// underState returns the path below "state/" for an archive name.
func underState(clean string) (string, bool) {
	if clean == stateRoot {
		return "", true
	}
	rel, ok := strings.CutPrefix(clean, stateRoot+"/")
	return rel, ok
}
