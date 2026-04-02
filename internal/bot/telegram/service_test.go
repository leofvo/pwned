package telegram

import "testing"

func TestParseIdentifyFiltersSinglePhone(t *testing.T) {
	t.Parallel()

	filters, err := parseIdentifyFilters("0611223344")
	if err != nil {
		t.Fatalf("parseIdentifyFilters() error = %v", err)
	}
	if filters.Phone != "611223344" {
		t.Fatalf("Phone = %q, want 611223344", filters.Phone)
	}
}

func TestParseIdentifyFiltersKeyValue(t *testing.T) {
	t.Parallel()

	filters, err := parseIdentifyFilters("phone=0611223344 firstname=John lastname=Doe")
	if err != nil {
		t.Fatalf("parseIdentifyFilters() error = %v", err)
	}
	if filters.Phone != "611223344" {
		t.Fatalf("Phone = %q, want 611223344", filters.Phone)
	}
	if filters.FirstName != "john" {
		t.Fatalf("FirstName = %q, want john", filters.FirstName)
	}
	if filters.LastName != "doe" {
		t.Fatalf("LastName = %q, want doe", filters.LastName)
	}
}

func TestParseIdentifyFiltersRejectsInvalidInput(t *testing.T) {
	t.Parallel()

	_, err := parseIdentifyFilters("foo bar")
	if err == nil {
		t.Fatalf("parseIdentifyFilters() expected error, got nil")
	}
}

func TestMatchesFilters(t *testing.T) {
	t.Parallel()

	line := "0611223344,secret,John,Doe,extra"

	if !matchesFilters(line, searchFilters{Phone: "611223"}) {
		t.Fatalf("matchesFilters() should match by phone")
	}
	if !matchesFilters(line, searchFilters{FirstName: "john"}) {
		t.Fatalf("matchesFilters() should match by firstname")
	}
	if !matchesFilters(line, searchFilters{LastName: "doe"}) {
		t.Fatalf("matchesFilters() should match by lastname")
	}
	if matchesFilters(line, searchFilters{LastName: "smith"}) {
		t.Fatalf("matchesFilters() should not match")
	}
}
