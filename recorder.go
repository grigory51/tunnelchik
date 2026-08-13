package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type sessionIdentity struct {
	Subject string `json:"subject"`
	Name    string `json:"name,omitempty"`
	Email   string `json:"email,omitempty"`
}

type sessionMetadata struct {
	SessionID             string           `json:"session_id"`
	StartedAt             time.Time        `json:"started_at"`
	EndedAt               time.Time        `json:"ended_at,omitempty"`
	SourceAddress         string           `json:"source_address"`
	Route                 string           `json:"route"`
	TargetAddress         string           `json:"target_address"`
	TargetUser            string           `json:"target_user"`
	InboundKeyFingerprint string           `json:"inbound_key_fingerprint"`
	AgentKeyFingerprints  []string         `json:"agent_key_fingerprints,omitempty"`
	Identity              *sessionIdentity `json:"identity,omitempty"`
	Authorization         string           `json:"authorization"`
	ExitStatus            *uint32          `json:"exit_status,omitempty"`
	ExitSignal            string           `json:"exit_signal,omitempty"`
	FailureCode           string           `json:"failure_code,omitempty"`
}

type sessionRecorder struct {
	mutex     sync.Mutex
	startedAt time.Time
	directory string
	cast      *os.File
	input     *os.File
	metadata  sessionMetadata
	closed    bool
}

type inputLogWriter struct {
	recorder *sessionRecorder
}

func newSessionRecorder(root string, metadata sessionMetadata) (*sessionRecorder, error) {
	now := time.Now().UTC()
	sessionIDBytes := make([]byte, 16)
	if _, err := rand.Read(sessionIDBytes); err != nil {
		return nil, err
	}
	metadata.SessionID = hex.EncodeToString(sessionIDBytes)
	metadata.StartedAt = now
	metadata.Authorization = "pending"

	dayDirectory := filepath.Join(root, now.Format("2006"), now.Format("01"), now.Format("02"))
	if err := os.MkdirAll(dayDirectory, 0o700); err != nil {
		return nil, err
	}
	for _, directoryToCheck := range []string{
		filepath.Join(root, now.Format("2006")),
		filepath.Join(root, now.Format("2006"), now.Format("01")),
		dayDirectory,
	} {
		info, err := os.Stat(directoryToCheck)
		if err != nil {
			return nil, err
		}
		if !info.IsDir() || info.Mode().Perm() != 0o700 {
			return nil, fmt.Errorf("recordings directory %q must have mode 0700", directoryToCheck)
		}
	}
	directory := filepath.Join(dayDirectory, metadata.SessionID)
	if err := os.Mkdir(directory, 0o700); err != nil {
		return nil, err
	}
	directoryInfo, err := os.Stat(directory)
	if err != nil {
		return nil, err
	}
	if !directoryInfo.IsDir() || directoryInfo.Mode().Perm() != 0o700 {
		return nil, fmt.Errorf("recordings directory %q must have mode 0700", directory)
	}
	cast, err := os.OpenFile(filepath.Join(directory, "terminal.cast"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, err
	}
	input, err := os.OpenFile(filepath.Join(directory, "input.jsonl"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, errors.Join(err, cast.Close())
	}
	recorder := &sessionRecorder{
		startedAt: now,
		directory: directory,
		cast:      cast,
		input:     input,
		metadata:  metadata,
	}
	header := struct {
		Version   int               `json:"version"`
		Width     int               `json:"width"`
		Height    int               `json:"height"`
		Timestamp int64             `json:"timestamp"`
		Env       map[string]string `json:"env"`
	}{2, 80, 24, now.Unix(), map[string]string{"TERM": "xterm-256color"}}
	if err := recorder.writeJSONLine(cast, header); err != nil {
		return nil, errors.Join(err, cast.Close(), input.Close())
	}
	if err := recorder.writeMetadataLocked(); err != nil {
		return nil, errors.Join(err, cast.Close(), input.Close())
	}
	return recorder, nil
}

func (r *sessionRecorder) Write(data []byte) (int, error) {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	if r.closed {
		return 0, os.ErrClosed
	}
	if err := r.writeJSONLine(r.cast, []any{time.Since(r.startedAt).Seconds(), "o", string(data)}); err != nil {
		return 0, err
	}
	return len(data), nil
}

func (r *sessionRecorder) inputWriter() io.Writer {
	return inputLogWriter{recorder: r}
}

func (w inputLogWriter) Write(data []byte) (int, error) {
	w.recorder.mutex.Lock()
	defer w.recorder.mutex.Unlock()
	if w.recorder.closed {
		return 0, os.ErrClosed
	}
	event := map[string]any{
		"time": time.Since(w.recorder.startedAt).Seconds(),
		"type": "input",
		"data": base64.StdEncoding.EncodeToString(data),
	}
	if err := w.recorder.writeJSONLine(w.recorder.input, event); err != nil {
		return 0, err
	}
	return len(data), nil
}

func (r *sessionRecorder) recordExec(command string) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	if r.closed {
		return os.ErrClosed
	}
	return r.writeJSONLine(r.input, map[string]any{
		"time":    time.Since(r.startedAt).Seconds(),
		"type":    "exec",
		"command": command,
	})
}

func (r *sessionRecorder) recordResize(columns, rows uint32) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	if r.closed {
		return os.ErrClosed
	}
	return r.writeJSONLine(r.cast, []any{
		time.Since(r.startedAt).Seconds(),
		"r",
		fmt.Sprintf("%dx%d", columns, rows),
	})
}

func (r *sessionRecorder) setAgentFingerprints(fingerprints []string) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	r.metadata.AgentKeyFingerprints = append([]string(nil), fingerprints...)
	return r.writeMetadataLocked()
}

func (r *sessionRecorder) setAuthorized(identity sessionIdentity) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	r.metadata.Identity = &identity
	r.metadata.Authorization = "allowed"
	return r.writeMetadataLocked()
}

func (r *sessionRecorder) setDenied(failureCode string) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	r.metadata.Authorization = "denied"
	r.metadata.FailureCode = failureCode
	return r.writeMetadataLocked()
}

func (r *sessionRecorder) setExitStatus(status uint32) {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	r.metadata.ExitStatus = &status
}

func (r *sessionRecorder) setExitSignal(signal string) {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	r.metadata.ExitSignal = signal
}

func (r *sessionRecorder) fail(code string) {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	if r.metadata.FailureCode == "" {
		r.metadata.FailureCode = code
	}
}

func (r *sessionRecorder) Close() error {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	if r.closed {
		return nil
	}
	r.closed = true
	r.metadata.EndedAt = time.Now().UTC()
	return errors.Join(r.cast.Close(), r.input.Close(), r.writeMetadataLocked())
}

func (r *sessionRecorder) writeJSONLine(writer io.Writer, value any) error {
	encoded, err := json.Marshal(value)
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	_, err = writer.Write(encoded)
	return err
}

func (r *sessionRecorder) writeMetadataLocked() error {
	temporaryPath := filepath.Join(r.directory, ".metadata.json.tmp")
	defer os.Remove(temporaryPath)
	file, err := os.OpenFile(temporaryPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(file)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(r.metadata); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryPath, filepath.Join(r.directory, "metadata.json"))
}
