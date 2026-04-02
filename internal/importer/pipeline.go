package importer

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

var (
	emailRegex = regexp.MustCompile(`(?i)[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}`)
	phoneRegex = regexp.MustCompile(`\+?[0-9][0-9\-\s().]{6,}[0-9]`)
)

type normalizeResult struct {
	DetectedFormat   string
	RecordsProcessed int64
	LastCheckpoint   string
	Chunks           []ManifestChunk
}

func detectFormat(filePath string, formatOverride string) string {
	override := strings.ToLower(strings.TrimSpace(formatOverride))
	if override != "" && override != "auto" {
		return override
	}

	ext := strings.ToLower(filepath.Ext(filePath))
	switch ext {
	case ".csv":
		return "csv"
	case ".ndjson", ".jsonl":
		return "ndjson"
	case ".json":
		return "json"
	case ".txt", ".log":
		return "txt"
	default:
		return "txt"
	}
}

func (s *Service) normalizeAndUploadFile(
	ctx context.Context,
	opts Options,
	ingestID string,
	file inputFile,
	year string,
	month string,
	resumeEntry *ManifestFile,
	limits runtimeLimits,
) (normalizeResult, error) {
	detectedFormat := detectFormat(file.relPath, opts.Format)

	var (
		part             int
		chunks           []ManifestChunk
		currentFile      *os.File
		currentWriter    *bufio.Writer
		currentPath      string
		currentKey       string
		currentBytes     int64
		currentCount     int64
		totalRecords     int64
		lastCheckpoint   string
		resumeCheckpoint int64
		resumeReady      bool
	)

	if resumeEntry != nil {
		part = len(resumeEntry.NormalizedChunks)
		totalRecords = resumeEntry.RecordsProcessed
		lastCheckpoint = strings.TrimSpace(resumeEntry.LastCheckpoint)
		chunks = append(chunks, resumeEntry.NormalizedChunks...)
		if checkpoint, ok := checkpointOrdinal(lastCheckpoint); ok {
			resumeCheckpoint = checkpoint
		} else if totalRecords > 0 || len(chunks) > 0 {
			return normalizeResult{}, fmt.Errorf("cannot resume %q: missing or invalid checkpoint %q", file.relPath, lastCheckpoint)
		}
	}
	resumeReady = resumeCheckpoint == 0

	buildResult := func() normalizeResult {
		return normalizeResult{
			DetectedFormat:   detectedFormat,
			RecordsProcessed: totalRecords,
			LastCheckpoint:   lastCheckpoint,
			Chunks:           chunks,
		}
	}

	openChunk := func() error {
		part++
		currentPath = normalizedLocalPath(s.cfg.NormalizedLocalDir, ingestID, file.relPath, part)
		currentKey = normalizedObjectKey(opts.Source, year, month, ingestID, file.relPath, part)

		if err := os.MkdirAll(filepath.Dir(currentPath), 0o755); err != nil {
			return fmt.Errorf("create normalized local directory: %w", err)
		}

		handle, err := os.Create(currentPath)
		if err != nil {
			return fmt.Errorf("create normalized chunk %q: %w", currentPath, err)
		}

		currentFile = handle
		currentWriter = bufio.NewWriterSize(handle, limits.WriterBufferBytes)
		currentBytes = 0
		currentCount = 0
		return nil
	}

	closeChunk := func() error {
		if currentFile == nil {
			return nil
		}

		if err := currentWriter.Flush(); err != nil {
			currentFile.Close()
			return fmt.Errorf("flush chunk writer %q: %w", currentPath, err)
		}
		if err := currentFile.Close(); err != nil {
			return fmt.Errorf("close chunk file %q: %w", currentPath, err)
		}

		sizeBytes, err := s.uploadLocalFileWithRetry(ctx, currentPath, currentKey, "application/x-ndjson")
		if err != nil {
			return err
		}

		chunks = append(chunks, ManifestChunk{
			Part:        part,
			LocalPath:   currentPath,
			ObjectKey:   currentKey,
			RecordCount: currentCount,
			SizeBytes:   sizeBytes,
		})

		currentFile = nil
		currentWriter = nil
		currentPath = ""
		currentKey = ""
		currentBytes = 0
		currentCount = 0
		return nil
	}

	writeNormalized := func(record map[string]any) error {
		payload, err := json.Marshal(record)
		if err != nil {
			return fmt.Errorf("marshal normalized record: %w", err)
		}
		payload = append(payload, '\n')
		payloadBytes := int64(len(payload))

		if payloadBytes > limits.ChunkMaxBytes {
			return fmt.Errorf("single normalized record exceeds chunk max bytes (%d)", limits.ChunkMaxBytes)
		}

		if currentFile == nil {
			if err := openChunk(); err != nil {
				return err
			}
		}

		wouldOverflowBytes := currentCount > 0 && (currentBytes+payloadBytes) > limits.ChunkMaxBytes
		wouldOverflowRecords := currentCount > 0 && int(currentCount) >= limits.ChunkMaxRecords
		if wouldOverflowBytes || wouldOverflowRecords {
			if err := closeChunk(); err != nil {
				return err
			}
			if err := openChunk(); err != nil {
				return err
			}
		}

		written, err := currentWriter.Write(payload)
		if err != nil {
			return fmt.Errorf("write normalized chunk %q: %w", currentPath, err)
		}

		currentBytes += int64(written)
		currentCount++
		totalRecords++
		return nil
	}

	err := s.streamRecords(file.absPath, detectedFormat, opts, limits, func(fields map[string]any, checkpoint string) error {
		lastCheckpoint = checkpoint

		if !resumeReady {
			currentCheckpoint, ok := checkpointOrdinal(checkpoint)
			if ok && currentCheckpoint <= resumeCheckpoint {
				return nil
			}
			resumeReady = true
		}

		normalized, keep := normalizeRecord(opts.Source, file.relPath, ingestID, totalRecords+1, detectedFormat, fields)
		if !keep {
			return nil
		}
		return writeNormalized(normalized)
	})
	if err != nil {
		closeErr := closeChunk()
		result := buildResult()
		if closeErr != nil {
			return result, errors.Join(err, closeErr)
		}
		return result, err
	}

	if err := closeChunk(); err != nil {
		return buildResult(), err
	}

	return buildResult(), nil
}

type emitFunc func(fields map[string]any, checkpoint string) error

func (s *Service) streamRecords(filePath string, format string, opts Options, limits runtimeLimits, emit emitFunc) error {
	switch format {
	case "csv":
		return s.streamCSV(filePath, opts, limits, emit)
	case "json":
		return s.streamJSON(filePath, limits, emit)
	case "ndjson":
		return s.streamNDJSON(filePath, limits, emit)
	case "txt":
		return s.streamTXT(filePath, limits, emit)
	default:
		return fmt.Errorf("unsupported format %q", format)
	}
}

func (s *Service) streamCSV(filePath string, opts Options, limits runtimeLimits, emit emitFunc) error {
	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("open csv file %q: %w", filePath, err)
	}
	defer file.Close()

	readerBufferBytes := limits.WriterBufferBytes * 2
	if readerBufferBytes < 64*1024 {
		readerBufferBytes = 64 * 1024
	}
	reader := csv.NewReader(bufio.NewReaderSize(file, readerBufferBytes))
	reader.FieldsPerRecord = -1
	reader.ReuseRecord = true
	reader.LazyQuotes = true
	reader.TrimLeadingSpace = true

	line := int64(0)
	var headers []string

	if opts.CSVNoHeader {
		headers = make([]string, 0, len(opts.CSVHeaders))
		for _, header := range opts.CSVHeaders {
			headers = append(headers, canonicalizeKey(header))
		}
	} else {
		headerRow, err := reader.Read()
		if err != nil {
			return fmt.Errorf("read csv header %q: %w", filePath, err)
		}
		line = 1
		effectiveHeaderRow := headerRow
		if len(opts.CSVHeaders) > 0 {
			effectiveHeaderRow = opts.CSVHeaders
		}
		headers = make([]string, len(effectiveHeaderRow))
		for i, header := range effectiveHeaderRow {
			headers[i] = canonicalizeKey(header)
		}
	}
	for {
		record, err := reader.Read()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("read csv row %d in %q: %w", line+1, filePath, err)
		}
		line++

		fields := make(map[string]any, len(headers))
		for i, key := range headers {
			if key == "" {
				continue
			}
			if i >= len(record) {
				continue
			}
			fields[key] = record[i]
		}

		checkpoint := fmt.Sprintf("line:%d", line)
		if err := emit(fields, checkpoint); err != nil {
			return err
		}
	}
}

func (s *Service) streamNDJSON(filePath string, limits runtimeLimits, emit emitFunc) error {
	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("open ndjson file %q: %w", filePath, err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), limits.ParserMaxLineBytes)

	var line int64
	for scanner.Scan() {
		line++
		raw := strings.TrimSpace(scanner.Text())
		if raw == "" {
			continue
		}

		var decoded any
		if err := json.Unmarshal([]byte(raw), &decoded); err != nil {
			return fmt.Errorf("decode ndjson line %d in %q: %w", line, filePath, err)
		}
		fields := coerceToMap(decoded)
		checkpoint := fmt.Sprintf("line:%d", line)
		if err := emit(fields, checkpoint); err != nil {
			return err
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("scan ndjson file %q: %w", filePath, err)
	}
	return nil
}

func (s *Service) streamJSON(filePath string, _ runtimeLimits, emit emitFunc) error {
	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("open json file %q: %w", filePath, err)
	}
	defer file.Close()

	dec := json.NewDecoder(bufio.NewReaderSize(file, 128*1024))
	token, err := dec.Token()
	if err != nil {
		return fmt.Errorf("read first json token in %q: %w", filePath, err)
	}

	delim, isDelim := token.(json.Delim)
	if !isDelim {
		return fmt.Errorf("unsupported json root in %q: expected object or array", filePath)
	}

	switch delim {
	case '[':
		index := int64(0)
		for dec.More() {
			index++
			var decoded any
			if err := dec.Decode(&decoded); err != nil {
				return fmt.Errorf("decode json array item %d in %q: %w", index, filePath, err)
			}

			fields := coerceToMap(decoded)
			if err := emit(fields, fmt.Sprintf("item:%d", index)); err != nil {
				return err
			}
		}
		if _, err := dec.Token(); err != nil {
			return fmt.Errorf("consume json array end in %q: %w", filePath, err)
		}
		return nil
	case '{':
		decoded, err := decodeObjectFromOpenBrace(dec)
		if err != nil {
			return fmt.Errorf("decode json object in %q: %w", filePath, err)
		}
		return emit(decoded, "item:1")
	default:
		return fmt.Errorf("unsupported json delimiter %q in %q", string(delim), filePath)
	}
}

func (s *Service) streamTXT(filePath string, limits runtimeLimits, emit emitFunc) error {
	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("open txt file %q: %w", filePath, err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), limits.ParserMaxLineBytes)

	var line int64
	for scanner.Scan() {
		line++
		raw := strings.TrimSpace(scanner.Text())
		if raw == "" {
			continue
		}

		fields := parseTextLine(raw)
		fields["raw_line"] = raw
		if err := emit(fields, fmt.Sprintf("line:%d", line)); err != nil {
			return err
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("scan txt file %q: %w", filePath, err)
	}
	return nil
}

func decodeObjectFromOpenBrace(dec *json.Decoder) (map[string]any, error) {
	out := make(map[string]any)
	for dec.More() {
		keyToken, err := dec.Token()
		if err != nil {
			return nil, err
		}
		key, ok := keyToken.(string)
		if !ok {
			return nil, fmt.Errorf("unexpected json key token type %T", keyToken)
		}

		var value any
		if err := dec.Decode(&value); err != nil {
			return nil, err
		}
		out[key] = value
	}
	if _, err := dec.Token(); err != nil {
		return nil, err
	}
	return out, nil
}

func coerceToMap(value any) map[string]any {
	switch typed := value.(type) {
	case map[string]any:
		return typed
	case []any:
		return map[string]any{"values": typed}
	default:
		return map[string]any{"value": typed}
	}
}

func parseTextLine(line string) map[string]any {
	fields := make(map[string]any)

	delimiters := []string{"|", ";", "\t", ":", ","}
	for _, delimiter := range delimiters {
		parts := strings.Split(line, delimiter)
		if len(parts) < 2 || len(parts) > 8 {
			continue
		}
		for i := range parts {
			parts[i] = strings.TrimSpace(parts[i])
		}

		if fields["email"] == nil {
			for _, part := range parts {
				if emailRegex.MatchString(part) {
					fields["email"] = emailRegex.FindString(part)
					break
				}
			}
		}

		if len(parts) >= 1 && fields["username"] == nil && !emailRegex.MatchString(parts[0]) {
			fields["username"] = parts[0]
		}
		if len(parts) >= 2 && fields["password"] == nil {
			fields["password"] = parts[1]
		}
		if len(parts) >= 3 && fields["firstname"] == nil {
			fields["firstname"] = parts[2]
		}
		if len(parts) >= 4 && fields["lastname"] == nil {
			fields["lastname"] = parts[3]
		}
		break
	}

	if fields["email"] == nil {
		if found := emailRegex.FindString(line); found != "" {
			fields["email"] = found
		}
	}
	if fields["phone"] == nil {
		if found := phoneRegex.FindString(line); found != "" {
			fields["phone"] = found
		}
	}

	return fields
}

func normalizeRecord(
	source string,
	relativePath string,
	ingestID string,
	offset int64,
	format string,
	rawFields map[string]any,
) (map[string]any, bool) {
	clean := normalizeFieldMap(rawFields)
	out := map[string]any{
		"source":        source,
		"source_file":   relativePath,
		"ingest_id":     ingestID,
		"record_offset": offset,
		"input_format":  format,
	}

	for _, mapping := range fieldMappings {
		assignCanonicalField(out, clean, mapping.Canonical, mapping.Aliases...)
	}

	if asString(out["address"]) == "" {
		if combinedAddress := deriveAddress(clean, out); combinedAddress != "" {
			out["address"] = combinedAddress
		}
	}

	if value, ok := clean["raw_line"]; ok {
		out["raw_line"] = value
	}

	if asString(out["email"]) == "" {
		if found := firstRegexMatchFromValues(clean, emailRegex); found != "" {
			out["email"] = strings.ToLower(found)
		}
	}
	if asString(out["phone"]) == "" {
		if found := firstRegexMatchFromValues(clean, phoneRegex); found != "" {
			out["phone"] = normalizePhone(found)
		}
	}

	if phone := asString(out["phone"]); phone != "" {
		out["phone"] = normalizePhone(phone)
	}
	if email := asString(out["email"]); email != "" {
		out["email"] = strings.ToLower(strings.TrimSpace(email))
	}

	out["record_id"] = buildRecordID(
		source,
		relativePath,
		offset,
		asString(out["email"]),
		asString(out["phone"]),
		asString(out["username"]),
		asString(out["firstname"]),
		asString(out["lastname"]),
		asString(out["password_hash"]),
		asString(out["password"]),
	)

	extra := collectExtraFields(clean)
	if len(extra) > 0 {
		payload, _ := json.Marshal(extra)
		out["extra_json"] = string(payload)
	}

	keep := false
	for _, field := range []string{
		"email",
		"phone",
		"username",
		"firstname",
		"lastname",
		"address",
		"city",
		"country",
		"gender",
		"birthday",
		"ip",
		"password",
		"password_hash",
		"raw_line",
	} {
		if asString(out[field]) != "" {
			keep = true
			break
		}
	}
	return out, keep
}

func normalizeFieldMap(fields map[string]any) map[string]string {
	out := make(map[string]string, len(fields))
	for key, value := range fields {
		normalizedKey := canonicalizeKey(key)
		if normalizedKey == "" {
			continue
		}
		stringValue := strings.TrimSpace(asString(value))
		if stringValue == "" {
			continue
		}
		out[normalizedKey] = stringValue
	}
	return out
}

func canonicalizeKey(input string) string {
	key := strings.TrimSpace(input)
	key = strings.TrimPrefix(key, "\uFEFF")
	key = strings.ToLower(key)
	key = strings.ReplaceAll(key, "-", "_")
	key = strings.ReplaceAll(key, " ", "_")
	key = strings.ReplaceAll(key, ".", "_")
	return key
}

func asString(value any) string {
	if value == nil {
		return ""
	}
	switch typed := value.(type) {
	case string:
		return strings.TrimSpace(typed)
	case []byte:
		return strings.TrimSpace(string(typed))
	default:
		rendered := strings.TrimSpace(fmt.Sprintf("%v", typed))
		if rendered == "<nil>" {
			return ""
		}
		return rendered
	}
}

func assignCanonicalField(dst map[string]any, src map[string]string, dstKey string, aliases ...string) {
	for _, alias := range aliases {
		if value, ok := src[canonicalizeKey(alias)]; ok && strings.TrimSpace(value) != "" {
			dst[dstKey] = strings.TrimSpace(value)
			return
		}
	}
}

func normalizePhone(raw string) string {
	value := strings.TrimSpace(raw)
	value = strings.ReplaceAll(value, " ", "")
	value = strings.ReplaceAll(value, "-", "")
	value = strings.ReplaceAll(value, "(", "")
	value = strings.ReplaceAll(value, ")", "")
	value = strings.ReplaceAll(value, ".", "")
	return value
}

var addressPartKeys = []string{
	"street",
	"street_name",
	"street_address",
	"house_number",
	"address_line1",
	"address1",
	"address_line2",
	"address2",
	"postal_code",
	"postcode",
	"zip_code",
	"zipcode",
	"zip",
	"city",
	"state",
	"province",
	"region",
	"country",
}

func deriveAddress(clean map[string]string, out map[string]any) string {
	parts := make([]string, 0, len(addressPartKeys))
	seen := map[string]struct{}{}

	add := func(value string) {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			return
		}
		dedupeKey := strings.ToLower(trimmed)
		if _, ok := seen[dedupeKey]; ok {
			return
		}
		seen[dedupeKey] = struct{}{}
		parts = append(parts, trimmed)
	}

	for _, key := range addressPartKeys {
		add(clean[key])
	}
	add(asString(out["city"]))
	add(asString(out["country"]))

	if len(parts) == 0 {
		return ""
	}
	return strings.Join(parts, ", ")
}

func firstRegexMatchFromValues(values map[string]string, pattern *regexp.Regexp) string {
	for _, value := range values {
		if matched := pattern.FindString(value); matched != "" {
			return matched
		}
	}
	return ""
}

func buildRecordID(parts ...any) string {
	builder := strings.Builder{}
	for i, part := range parts {
		if i > 0 {
			builder.WriteString("|")
		}
		builder.WriteString(asString(part))
	}

	sum := sha256.Sum256([]byte(builder.String()))
	return hex.EncodeToString(sum[:])
}

var canonicalFieldKeys = map[string]struct{}{
	"source":        {},
	"source_file":   {},
	"ingest_id":     {},
	"record_offset": {},
	"input_format":  {},
	"record_id":     {},
	"raw_line":      {},
}

func init() {
	for _, mapping := range fieldMappings {
		canonicalFieldKeys[mapping.Canonical] = struct{}{}
	}
}

func collectExtraFields(values map[string]string) map[string]string {
	extra := make(map[string]string)
	for key, value := range values {
		if _, ok := canonicalFieldKeys[key]; ok {
			continue
		}
		extra[key] = value
	}
	return extra
}

func checkpointOrdinal(value string) (int64, bool) {
	parts := strings.SplitN(strings.TrimSpace(value), ":", 2)
	if len(parts) != 2 {
		return 0, false
	}
	parsed, err := strconv.ParseInt(strings.TrimSpace(parts[1]), 10, 64)
	if err != nil || parsed < 0 {
		return 0, false
	}
	return parsed, true
}
