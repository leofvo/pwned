package importer

import (
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"

	"github.com/leofvo/pwned/internal/config"
)

const (
	minImportMemoryBytes int64 = 8 * 1024 * 1024
)

type runtimeLimits struct {
	MaxMemoryBytes     int64
	ChunkMaxBytes      int64
	ChunkMaxRecords    int
	ParserMaxLineBytes int
	WriterBufferBytes  int
}

var byteSizePattern = regexp.MustCompile(`^([0-9]+(?:\.[0-9]+)?)\s*([a-zA-Z]*)$`)

func deriveRuntimeLimits(maxMemory string, cfg config.Config) (runtimeLimits, error) {
	budget, err := parseByteSize(maxMemory)
	if err != nil {
		return runtimeLimits{}, fmt.Errorf("parse max memory: %w", err)
	}
	if budget < minImportMemoryBytes {
		return runtimeLimits{}, fmt.Errorf("max memory must be >= %d bytes (8MiB), got %d", minImportMemoryBytes, budget)
	}

	chunkMaxBytes := minInt64(cfg.ChunkMaxBytes, budget/2)
	if chunkMaxBytes < 128*1024 {
		return runtimeLimits{}, fmt.Errorf("max memory too small for chunking: need at least 128KiB chunk budget, got %d", chunkMaxBytes)
	}

	parserMaxLineBytes := minInt64(int64(cfg.ParserMaxLineBytes), budget/4)
	if parserMaxLineBytes < 64*1024 {
		return runtimeLimits{}, fmt.Errorf("max memory too small for parser line buffer: got %d", parserMaxLineBytes)
	}

	writerBufferBytes := budget / 512
	if writerBufferBytes > 64*1024 {
		writerBufferBytes = 64 * 1024
	}
	if writerBufferBytes < 8*1024 {
		writerBufferBytes = 8 * 1024
	}

	chunkMaxRecords := cfg.ChunkMaxRecords
	if cfg.ChunkMaxBytes > 0 && chunkMaxBytes < cfg.ChunkMaxBytes {
		scaled := int((int64(cfg.ChunkMaxRecords) * chunkMaxBytes) / cfg.ChunkMaxBytes)
		if scaled < 1 {
			scaled = 1
		}
		if scaled < chunkMaxRecords {
			chunkMaxRecords = scaled
		}
	}
	if chunkMaxRecords < 1 {
		chunkMaxRecords = 1
	}

	return runtimeLimits{
		MaxMemoryBytes:     budget,
		ChunkMaxBytes:      chunkMaxBytes,
		ChunkMaxRecords:    chunkMaxRecords,
		ParserMaxLineBytes: int(parserMaxLineBytes),
		WriterBufferBytes:  int(writerBufferBytes),
	}, nil
}

func parseByteSize(raw string) (int64, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return 0, fmt.Errorf("empty size")
	}

	match := byteSizePattern.FindStringSubmatch(trimmed)
	if len(match) != 3 {
		return 0, fmt.Errorf("invalid size %q", raw)
	}

	number, err := strconv.ParseFloat(match[1], 64)
	if err != nil {
		return 0, fmt.Errorf("invalid numeric value %q", match[1])
	}
	if number <= 0 {
		return 0, fmt.Errorf("size must be > 0")
	}

	unit := strings.ToLower(strings.TrimSpace(match[2]))
	multiplier, ok := unitMultipliers[unit]
	if !ok {
		return 0, fmt.Errorf("unsupported unit %q", match[2])
	}

	size := number * multiplier
	if size > float64(math.MaxInt64) {
		return 0, fmt.Errorf("size overflows int64")
	}
	bytes := int64(size)
	if bytes <= 0 {
		return 0, fmt.Errorf("size must be at least 1 byte")
	}
	return bytes, nil
}

var unitMultipliers = map[string]float64{
	"":    1,
	"b":   1,
	"k":   1000,
	"kb":  1000,
	"m":   1000 * 1000,
	"mb":  1000 * 1000,
	"g":   1000 * 1000 * 1000,
	"gb":  1000 * 1000 * 1000,
	"t":   1000 * 1000 * 1000 * 1000,
	"tb":  1000 * 1000 * 1000 * 1000,
	"ki":  1024,
	"kib": 1024,
	"mi":  1024 * 1024,
	"mib": 1024 * 1024,
	"gi":  1024 * 1024 * 1024,
	"gib": 1024 * 1024 * 1024,
	"ti":  1024 * 1024 * 1024 * 1024,
	"tib": 1024 * 1024 * 1024 * 1024,
}

func minInt64(a int64, b int64) int64 {
	if a < b {
		return a
	}
	return b
}
