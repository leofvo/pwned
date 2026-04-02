package bot

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	telegrambot "github.com/leofvo/pwned/internal/bot/telegram"
	"github.com/leofvo/pwned/internal/config"
)

const (
	platformTelegram  = "telegram"
	defaultLeaksGlob  = "./leaks/*.txt"
	defaultStopWait   = 10 * time.Second
	defaultPollPeriod = 250 * time.Millisecond
)

type Service struct {
	cfg    config.Config
	logger *slog.Logger
}

type StartOptions struct {
	Platform  string
	Token     string
	LeaksGlob string
}

type RunOptions struct {
	Platform  string
	Token     string
	LeaksGlob string
}

type StatusOptions struct {
	Platform string
}

type StopOptions struct {
	Platform string
	Timeout  time.Duration
}

type StartResult struct {
	Platform  string    `json:"platform"`
	PID       int       `json:"pid"`
	Running   bool      `json:"running"`
	PIDFile   string    `json:"pid_file"`
	LogFile   string    `json:"log_file"`
	StartedAt time.Time `json:"started_at"`
}

type StatusResult struct {
	Platform     string `json:"platform"`
	Running      bool   `json:"running"`
	PID          int    `json:"pid,omitempty"`
	PIDFile      string `json:"pid_file"`
	LogFile      string `json:"log_file"`
	StalePIDFile bool   `json:"stale_pid_file"`
}

type StopResult struct {
	Platform string `json:"platform"`
	Stopped  bool   `json:"stopped"`
	WasRun   bool   `json:"was_running"`
	PID      int    `json:"pid,omitempty"`
	PIDFile  string `json:"pid_file"`
}

func NewService(cfg config.Config, logger *slog.Logger) *Service {
	return &Service{
		cfg:    cfg,
		logger: logger,
	}
}

func (s *Service) Start(_ context.Context, opts StartOptions) (StartResult, error) {
	platform, err := normalizePlatform(opts.Platform)
	if err != nil {
		return StartResult{}, err
	}
	token := strings.TrimSpace(opts.Token)
	if token == "" {
		token = strings.TrimSpace(os.Getenv("TELEGRAM_BOT_TOKEN"))
	}
	if platform == platformTelegram && token == "" {
		return StartResult{}, fmt.Errorf("missing telegram token, pass --token or set TELEGRAM_BOT_TOKEN")
	}

	leaksGlob := normalizedLeaksGlob(opts.LeaksGlob)
	pidFile := pidFilePath(platform)
	logFile := logFilePath(platform)

	if err := os.MkdirAll(runtimeDir(), 0o755); err != nil {
		return StartResult{}, fmt.Errorf("create bot runtime directory: %w", err)
	}

	currentStatus, err := s.Status(context.Background(), StatusOptions{Platform: platform})
	if err != nil {
		return StartResult{}, err
	}
	if currentStatus.Running {
		return StartResult{}, fmt.Errorf("bot platform %q is already running with pid %d", platform, currentStatus.PID)
	}
	if currentStatus.StalePIDFile {
		_ = os.Remove(pidFile)
	}

	logHandle, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return StartResult{}, fmt.Errorf("open bot log file %q: %w", logFile, err)
	}
	defer logHandle.Close()

	exePath, err := os.Executable()
	if err != nil {
		return StartResult{}, fmt.Errorf("resolve executable path: %w", err)
	}

	args := []string{
		"bot",
		"run",
		"--platform", platform,
		"--leaks-glob", leaksGlob,
	}
	cmd := exec.Command(exePath, args...)
	cmd.Stdout = logHandle
	cmd.Stderr = logHandle
	cmd.Stdin = nil
	if token != "" {
		cmd.Env = upsertEnv(os.Environ(), "TELEGRAM_BOT_TOKEN", token)
	}

	if err := cmd.Start(); err != nil {
		return StartResult{}, fmt.Errorf("start bot process: %w", err)
	}
	pid := cmd.Process.Pid
	startedAt := time.Now().UTC()

	if err := os.WriteFile(pidFile, []byte(strconv.Itoa(pid)), 0o644); err != nil {
		return StartResult{}, fmt.Errorf("write pid file %q: %w", pidFile, err)
	}

	_ = writeStateSnapshot(platform, startedAt, pid, leaksGlob)
	_ = cmd.Process.Release()

	s.logger.Info("bot started", "platform", platform, "pid", pid)

	return StartResult{
		Platform:  platform,
		PID:       pid,
		Running:   true,
		PIDFile:   pidFile,
		LogFile:   logFile,
		StartedAt: startedAt,
	}, nil
}

func (s *Service) Run(ctx context.Context, opts RunOptions) error {
	platform, err := normalizePlatform(opts.Platform)
	if err != nil {
		return err
	}
	token := strings.TrimSpace(opts.Token)
	if token == "" {
		token = strings.TrimSpace(os.Getenv("TELEGRAM_BOT_TOKEN"))
	}
	if platform == platformTelegram && token == "" {
		return fmt.Errorf("missing telegram token, pass --token or set TELEGRAM_BOT_TOKEN")
	}

	leaksGlob := normalizedLeaksGlob(opts.LeaksGlob)
	defer cleanupPIDIfMatches(platform, os.Getpid())

	switch platform {
	case platformTelegram:
		return telegrambot.Run(ctx, telegrambot.Options{
			Token:     token,
			LeaksGlob: leaksGlob,
		}, s.logger)
	default:
		return fmt.Errorf("unsupported platform %q", platform)
	}
}

func (s *Service) Status(_ context.Context, opts StatusOptions) (StatusResult, error) {
	platform, err := normalizePlatform(opts.Platform)
	if err != nil {
		return StatusResult{}, err
	}

	pidFile := pidFilePath(platform)
	logFile := logFilePath(platform)
	pid, err := readPID(pidFile)
	if err != nil {
		if os.IsNotExist(err) {
			return StatusResult{
				Platform: platform,
				Running:  false,
				PIDFile:  pidFile,
				LogFile:  logFile,
			}, nil
		}
		return StatusResult{}, fmt.Errorf("read pid file %q: %w", pidFile, err)
	}

	running := isPIDRunning(pid)
	return StatusResult{
		Platform:     platform,
		Running:      running,
		PID:          pid,
		PIDFile:      pidFile,
		LogFile:      logFile,
		StalePIDFile: !running,
	}, nil
}

func (s *Service) Stop(_ context.Context, opts StopOptions) (StopResult, error) {
	platform, err := normalizePlatform(opts.Platform)
	if err != nil {
		return StopResult{}, err
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = defaultStopWait
	}
	pidFile := pidFilePath(platform)

	status, err := s.Status(context.Background(), StatusOptions{Platform: platform})
	if err != nil {
		return StopResult{}, err
	}
	if !status.Running {
		_ = os.Remove(pidFile)
		return StopResult{
			Platform: platform,
			Stopped:  true,
			WasRun:   false,
			PIDFile:  pidFile,
		}, nil
	}

	process, err := os.FindProcess(status.PID)
	if err != nil {
		return StopResult{}, fmt.Errorf("find process %d: %w", status.PID, err)
	}

	if err := process.Signal(syscall.SIGTERM); err != nil {
		if !strings.Contains(strings.ToLower(err.Error()), "process already finished") {
			return StopResult{}, fmt.Errorf("send SIGTERM to pid %d: %w", status.PID, err)
		}
	}

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if !isPIDRunning(status.PID) {
			_ = os.Remove(pidFile)
			s.logger.Info("bot stopped", "platform", platform, "pid", status.PID)
			return StopResult{
				Platform: platform,
				Stopped:  true,
				WasRun:   true,
				PID:      status.PID,
				PIDFile:  pidFile,
			}, nil
		}
		time.Sleep(defaultPollPeriod)
	}

	_ = process.Signal(syscall.SIGKILL)
	time.Sleep(150 * time.Millisecond)
	_ = os.Remove(pidFile)

	return StopResult{
		Platform: platform,
		Stopped:  true,
		WasRun:   true,
		PID:      status.PID,
		PIDFile:  pidFile,
	}, nil
}

func runtimeDir() string {
	return filepath.Join(".state", "bot")
}

func pidFilePath(platform string) string {
	return filepath.Join(runtimeDir(), platform+".pid")
}

func logFilePath(platform string) string {
	return filepath.Join(runtimeDir(), platform+".log")
}

func stateFilePath(platform string) string {
	return filepath.Join(runtimeDir(), platform+".json")
}

func normalizePlatform(platform string) (string, error) {
	value := strings.ToLower(strings.TrimSpace(platform))
	if value == "" {
		value = platformTelegram
	}
	if value != platformTelegram {
		return "", fmt.Errorf("unsupported platform %q (supported: telegram)", platform)
	}
	return value, nil
}

func normalizedLeaksGlob(value string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return defaultLeaksGlob
	}
	return trimmed
}

func readPID(path string) (int, error) {
	payload, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(payload)))
	if err != nil || pid <= 0 {
		return 0, fmt.Errorf("invalid pid content in %q", path)
	}
	return pid, nil
}

func isPIDRunning(pid int) bool {
	if pid <= 0 {
		return false
	}
	process, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	err = process.Signal(syscall.Signal(0))
	return err == nil
}

func upsertEnv(base []string, key string, value string) []string {
	prefix := key + "="
	out := make([]string, 0, len(base)+1)
	for _, pair := range base {
		if strings.HasPrefix(pair, prefix) {
			continue
		}
		out = append(out, pair)
	}
	out = append(out, prefix+value)
	return out
}

type stateSnapshot struct {
	Platform  string    `json:"platform"`
	PID       int       `json:"pid"`
	StartedAt time.Time `json:"started_at"`
	LeaksGlob string    `json:"leaks_glob"`
}

func writeStateSnapshot(platform string, startedAt time.Time, pid int, leaksGlob string) error {
	payload, err := json.MarshalIndent(stateSnapshot{
		Platform:  platform,
		PID:       pid,
		StartedAt: startedAt,
		LeaksGlob: leaksGlob,
	}, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(stateFilePath(platform), payload, 0o644)
}

func cleanupPIDIfMatches(platform string, pid int) {
	pidFile := pidFilePath(platform)
	current, err := readPID(pidFile)
	if err != nil {
		return
	}
	if current == pid {
		_ = os.Remove(pidFile)
	}
}
