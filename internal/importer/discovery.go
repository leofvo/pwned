package importer

import (
	"crypto/rand"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

func discoverFiles(inputPath string, recursive bool) ([]inputFile, error) {
	cleanPath := filepath.Clean(strings.TrimSpace(inputPath))
	info, err := os.Stat(cleanPath)
	if err != nil {
		return nil, fmt.Errorf("stat input path %q: %w", cleanPath, err)
	}

	if !info.IsDir() {
		return []inputFile{
			{
				absPath: cleanPath,
				relPath: filepath.Base(cleanPath),
				size:    info.Size(),
			},
		}, nil
	}

	if !recursive {
		return nil, fmt.Errorf("input %q is a directory, pass --recursive to ingest folder trees", cleanPath)
	}

	files := make([]inputFile, 0)
	err = filepath.WalkDir(cleanPath, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}

		fileInfo, err := d.Info()
		if err != nil {
			return err
		}
		if !fileInfo.Mode().IsRegular() {
			return nil
		}

		relPath, err := filepath.Rel(cleanPath, path)
		if err != nil {
			return err
		}

		files = append(files, inputFile{
			absPath: path,
			relPath: relPath,
			size:    fileInfo.Size(),
		})
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walk input directory %q: %w", cleanPath, err)
	}

	sort.Slice(files, func(i int, j int) bool {
		return files[i].relPath < files[j].relPath
	})

	return files, nil
}

func rawObjectKey(source string, year string, month string, ingestID string, relativePath string) string {
	trimmedSource := sanitizePath(source)
	normalizedRelPath := strings.ReplaceAll(relativePath, string(filepath.Separator), "/")
	normalizedRelPath = sanitizePath(normalizedRelPath)
	return fmt.Sprintf("raw/%s/%s/%s/%s/%s", trimmedSource, year, month, ingestID, normalizedRelPath)
}

func normalizedObjectKey(source string, year string, month string, ingestID string, relativePath string, part int) string {
	base := sanitizePath(strings.TrimSuffix(relativePath, filepath.Ext(relativePath)))
	base = strings.ReplaceAll(base, "/", "_")
	return fmt.Sprintf("normalized/%s/%s/%s/%s/%s.part-%06d.ndjson", sanitizePath(source), year, month, ingestID, base, part)
}

func normalizedLocalPath(root string, ingestID string, relativePath string, part int) string {
	base := sanitizePath(strings.TrimSuffix(relativePath, filepath.Ext(relativePath)))
	base = strings.ReplaceAll(base, "/", "_")
	filename := fmt.Sprintf("%s.part-%06d.ndjson", base, part)
	return filepath.Join(root, ingestID, filename)
}

func sanitizePath(value string) string {
	v := strings.TrimSpace(value)
	v = strings.ReplaceAll(v, "..", "_")
	v = strings.ReplaceAll(v, "\\", "/")
	v = strings.TrimPrefix(v, "/")
	v = strings.TrimSpace(v)
	if v == "" {
		return "_"
	}
	return v
}

func newIngestID(now time.Time) (string, error) {
	buf := make([]byte, 4)
	if _, err := io.ReadFull(rand.Reader, buf); err != nil {
		return "", fmt.Errorf("generate ingest id: %w", err)
	}
	return fmt.Sprintf("%s-%x", now.Format("20060102T150405Z"), buf), nil
}
