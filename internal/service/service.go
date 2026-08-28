package service

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
)

type Paths struct {
	Binary  string
	DataDir string
	Unit    string
	System  bool
}

type Runner func(string, ...string) error

type Manager struct{ Run Runner }

func New() Manager {
	return Manager{Run: func(name string, arguments ...string) error {
		command := exec.Command(name, arguments...)
		command.Stdout, command.Stderr, command.Stdin = os.Stdout, os.Stderr, os.Stdin
		return command.Run()
	}}
}

func Resolve(system bool) (Paths, error) {
	if runtime.GOOS != "linux" {
		return Paths{}, errors.New("service installation currently requires Linux systemd")
	}
	if system {
		return Paths{Binary: "/usr/local/lib/watchpost-agent/watchpost-agent", DataDir: "/var/lib/watchpost-agent", Unit: "/etc/systemd/system/watchpost-agent.service", System: true}, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return Paths{}, err
	}
	return Paths{
		Binary: filepath.Join(home, ".local", "lib", "watchpost-agent", "watchpost-agent"),
		DataDir: filepath.Join(home, ".local", "share", "watchpost-agent"),
		Unit: filepath.Join(home, ".config", "systemd", "user", "watchpost-agent.service"),
	}, nil
}

func Unit(paths Paths) string {
	wanted := "default.target"
	if paths.System {
		wanted = "multi-user.target"
	}
	return fmt.Sprintf(`[Unit]
Description=Watchpost Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=%s --data-dir %s
Restart=on-failure
RestartSec=5s
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=%s

[Install]
WantedBy=%s
`, paths.Binary, paths.DataDir, paths.DataDir, wanted)
}

func (m Manager) Install(source string, paths Paths) error {
	if err := os.MkdirAll(paths.DataDir, 0700); err != nil {
		return err
	}
	if err := atomicCopy(source, paths.Binary, 0755); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(paths.Unit), 0755); err != nil {
		return err
	}
	if err := atomicWrite(paths.Unit, []byte(Unit(paths)), 0644); err != nil {
		return err
	}
	if err := m.systemctl(paths, "daemon-reload"); err != nil {
		return err
	}
	if err := m.systemctl(paths, "enable", "watchpost-agent.service"); err != nil {
		return err
	}
	return m.systemctl(paths, "restart", "watchpost-agent.service")
}

func (m Manager) Status(paths Paths) error {
	return m.systemctl(paths, "status", "--no-pager", "watchpost-agent.service")
}

func (m Manager) Uninstall(paths Paths) error {
	_ = m.systemctl(paths, "disable", "--now", "watchpost-agent.service")
	if err := os.Remove(paths.Unit); err != nil && !os.IsNotExist(err) {
		return err
	}
	_ = m.systemctl(paths, "daemon-reload")
	if err := os.Remove(paths.Binary); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func (m Manager) systemctl(paths Paths, arguments ...string) error {
	if !paths.System {
		arguments = append([]string{"--user"}, arguments...)
	}
	return m.Run("systemctl", arguments...)
}

func atomicCopy(source, destination string, mode os.FileMode) error {
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer input.Close()
	if err = os.MkdirAll(filepath.Dir(destination), 0755); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(destination), ".watchpost-agent-install-*")
	if err != nil {
		return err
	}
	name := temporary.Name()
	defer os.Remove(name)
	if _, err = io.Copy(temporary, input); err == nil {
		err = temporary.Chmod(mode)
	}
	if closeErr := temporary.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(name, destination)
}

func atomicWrite(destination string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(destination), 0755); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(destination), ".watchpost-agent-write-*")
	if err != nil {
		return err
	}
	name := temporary.Name()
	defer os.Remove(name)
	if err = temporary.Chmod(mode); err == nil {
		_, err = temporary.Write(data)
	}
	if closeErr := temporary.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(name, destination)
}
