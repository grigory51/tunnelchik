package main

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestSessionRecorderWritesStreamingFiles(t *testing.T) {
	recorder, err := newSessionRecorder(t.TempDir(), sessionMetadata{
		SourceAddress:         "127.0.0.1:1234",
		Route:                 "bots",
		TargetAddress:         "127.0.0.1:22",
		TargetUser:            "ozhegov",
		InboundKeyFingerprint: "SHA256:inbound",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := recorder.Write([]byte("hello\n")); err != nil {
		t.Fatal(err)
	}
	if _, err := recorder.inputWriter().Write([]byte("id\n")); err != nil {
		t.Fatal(err)
	}
	if err := recorder.recordExec("id"); err != nil {
		t.Fatal(err)
	}
	if err := recorder.recordResize(120, 40); err != nil {
		t.Fatal(err)
	}
	if err := recorder.setAuthorized(sessionIdentity{Subject: "user-1", Email: "user@example.com"}); err != nil {
		t.Fatal(err)
	}
	recorder.setExitStatus(0)
	if err := recorder.Close(); err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(recorder.directory)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o700 {
		t.Fatalf("unexpected directory mode: %04o", info.Mode().Perm())
	}
	for _, name := range []string{"metadata.json", "terminal.cast", "input.jsonl"} {
		info, err := os.Stat(filepath.Join(recorder.directory, name))
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("unexpected %s mode: %04o", name, info.Mode().Perm())
		}
	}

	cast, err := os.Open(filepath.Join(recorder.directory, "terminal.cast"))
	if err != nil {
		t.Fatal(err)
	}
	defer cast.Close()
	scanner := bufio.NewScanner(cast)
	lines := 0
	for scanner.Scan() {
		var value any
		if err := json.Unmarshal(scanner.Bytes(), &value); err != nil {
			t.Fatal(err)
		}
		lines++
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if lines != 3 {
		t.Fatalf("unexpected cast line count: %d", lines)
	}

	metadataBytes, err := os.ReadFile(filepath.Join(recorder.directory, "metadata.json"))
	if err != nil {
		t.Fatal(err)
	}
	var metadata sessionMetadata
	if err := json.Unmarshal(metadataBytes, &metadata); err != nil {
		t.Fatal(err)
	}
	if metadata.Authorization != "allowed" || metadata.Identity == nil || metadata.ExitStatus == nil || *metadata.ExitStatus != 0 {
		t.Fatalf("unexpected metadata: %+v", metadata)
	}
}
