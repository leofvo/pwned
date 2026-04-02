package telegram

import (
	"bufio"
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
)

const defaultPollTimeoutSeconds = 60

type Options struct {
	Token     string
	LeaksGlob string
}

type searchFilters struct {
	Phone     string
	FirstName string
	LastName  string
}

var identifyFilterArgRegex = regexp.MustCompile(`(?i)(phone|firstname|lastname)\s*[:=]\s*("(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|[^\s]+)`)

func Run(ctx context.Context, opts Options, logger *slog.Logger) error {
	token := strings.TrimSpace(opts.Token)
	if token == "" {
		return fmt.Errorf("telegram token is required")
	}

	leaksGlob := strings.TrimSpace(opts.LeaksGlob)
	if leaksGlob == "" {
		leaksGlob = "./leaks/*.txt"
	}

	bot, err := tgbotapi.NewBotAPI(token)
	if err != nil {
		return fmt.Errorf("create telegram bot client: %w", err)
	}

	logger.Info("telegram bot runner started", "leaks_glob", leaksGlob)

	offset := 0
	for {
		select {
		case <-ctx.Done():
			logger.Info("telegram bot runner stopped")
			return nil
		default:
		}

		updateConfig := tgbotapi.NewUpdate(offset)
		updateConfig.Timeout = defaultPollTimeoutSeconds
		updates, err := bot.GetUpdates(updateConfig)
		if err != nil {
			if ctx.Err() != nil {
				logger.Info("telegram bot runner stopped")
				return nil
			}
			logger.Error("telegram get updates failed", "error", err)
			time.Sleep(2 * time.Second)
			continue
		}

		for _, update := range updates {
			if update.UpdateID >= offset {
				offset = update.UpdateID + 1
			}
			if update.Message == nil {
				continue
			}
			handleMessage(ctx, bot, leaksGlob, update.Message)
		}
	}
}

func handleMessage(ctx context.Context, client *tgbotapi.BotAPI, leaksGlob string, message *tgbotapi.Message) {
	if strings.HasPrefix(message.Text, "/health") {
		sendMessage(client, message.Chat.ID, "online")
		return
	}

	if !strings.HasPrefix(message.Text, "/identify") {
		return
	}

	args := strings.TrimSpace(strings.TrimPrefix(message.Text, "/identify"))
	filters, err := parseIdentifyFilters(args)
	if err != nil {
		sendMessage(client, message.Chat.ID, "Usage: /identify <phone> OR /identify phone=<phone> firstname=<firstname> lastname=<lastname>")
		return
	}

	result, searchErr := searchLeaks(ctx, leaksGlob, filters)
	criteria := formatSearchFilters(filters)
	if searchErr != nil && len(strings.TrimSpace(result)) == 0 {
		sendMessage(client, message.Chat.ID, "No leaks found for: "+criteria)
		return
	}
	if len(strings.TrimSpace(result)) == 0 {
		sendMessage(client, message.Chat.ID, "No leaks found for: "+criteria)
		return
	}

	sendMessage(client, message.Chat.ID, fmt.Sprintf("Result for %s:\n%s", criteria, result))
}

func sendMessage(client *tgbotapi.BotAPI, chatID int64, text string) {
	_, _ = client.Send(tgbotapi.NewMessage(chatID, text))
}

func parseIdentifyFilters(args string) (searchFilters, error) {
	filters := searchFilters{}
	args = strings.TrimSpace(args)
	if args == "" {
		return filters, fmt.Errorf("missing search parameters")
	}

	matches := identifyFilterArgRegex.FindAllStringSubmatchIndex(args, -1)
	if len(matches) == 0 {
		fields := strings.Fields(args)
		if len(fields) != 1 {
			return filters, fmt.Errorf("invalid positional arguments")
		}
		filters.Phone = normalizePhone(fields[0])
		return filters, nil
	}

	consumed := make([]bool, len(args))
	for _, match := range matches {
		fullStart, fullEnd := match[0], match[1]
		keyStart, keyEnd := match[2], match[3]
		valStart, valEnd := match[4], match[5]

		for i := fullStart; i < fullEnd; i++ {
			consumed[i] = true
		}

		key := strings.ToLower(strings.TrimSpace(args[keyStart:keyEnd]))
		value := strings.TrimSpace(args[valStart:valEnd])
		value = strings.Trim(value, `"'`)
		if value == "" {
			return filters, fmt.Errorf("empty value for %s", key)
		}

		switch key {
		case "phone":
			filters.Phone = normalizePhone(value)
		case "firstname":
			filters.FirstName = strings.ToLower(value)
		case "lastname":
			filters.LastName = strings.ToLower(value)
		default:
			return filters, fmt.Errorf("unknown filter %q", key)
		}
	}

	var leftovers strings.Builder
	for i := 0; i < len(args); i++ {
		if consumed[i] {
			continue
		}
		leftovers.WriteByte(args[i])
	}
	if strings.TrimSpace(leftovers.String()) != "" {
		return filters, fmt.Errorf("unsupported argument format")
	}

	if filters.Phone == "" && filters.FirstName == "" && filters.LastName == "" {
		return filters, fmt.Errorf("no usable filters")
	}
	return filters, nil
}

func normalizePhone(phone string) string {
	phone = strings.TrimSpace(phone)
	phone = strings.ReplaceAll(phone, " ", "")
	phone = strings.ReplaceAll(phone, "(", "")
	phone = strings.ReplaceAll(phone, ")", "")
	phone = strings.ReplaceAll(phone, "+", "")

	re := regexp.MustCompile(`^(33|33\(0\))`)
	phone = re.ReplaceAllString(phone, "")
	if strings.HasPrefix(phone, "0") {
		phone = phone[1:]
	}
	return phone
}

func matchesFilters(line string, filters searchFilters) bool {
	parts := strings.SplitN(line, ",", 5)
	if len(parts) < 4 {
		return false
	}

	phone := normalizePhone(parts[0])
	firstName := strings.ToLower(strings.TrimSpace(parts[2]))
	lastName := strings.ToLower(strings.TrimSpace(parts[3]))

	if filters.Phone != "" && !strings.Contains(phone, filters.Phone) {
		return false
	}
	if filters.FirstName != "" && !strings.Contains(firstName, filters.FirstName) {
		return false
	}
	if filters.LastName != "" && !strings.Contains(lastName, filters.LastName) {
		return false
	}
	return true
}

func searchLeaks(ctx context.Context, leaksGlob string, filters searchFilters) (string, error) {
	files, err := filepath.Glob(leaksGlob)
	if err != nil {
		return "", err
	}
	if len(files) == 0 {
		return "", fmt.Errorf("no leak files found for glob %q", leaksGlob)
	}

	var results strings.Builder
	for _, filePath := range files {
		select {
		case <-ctx.Done():
			return results.String(), ctx.Err()
		default:
		}

		file, err := os.Open(filePath)
		if err != nil {
			return results.String(), err
		}

		scanner := bufio.NewScanner(file)
		scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

		isHeader := true
		for scanner.Scan() {
			if isHeader {
				isHeader = false
				continue
			}
			line := scanner.Text()
			if matchesFilters(line, filters) {
				results.WriteString(line)
				results.WriteByte('\n')
			}
		}

		if err := scanner.Err(); err != nil {
			file.Close()
			return results.String(), err
		}
		file.Close()
	}

	return results.String(), nil
}

func formatSearchFilters(filters searchFilters) string {
	parts := make([]string, 0, 3)
	if filters.Phone != "" {
		parts = append(parts, "phone="+filters.Phone)
	}
	if filters.FirstName != "" {
		parts = append(parts, "firstname="+filters.FirstName)
	}
	if filters.LastName != "" {
		parts = append(parts, "lastname="+filters.LastName)
	}
	return strings.Join(parts, ", ")
}
