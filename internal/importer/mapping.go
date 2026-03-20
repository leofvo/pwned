package importer

import "strings"

type FieldMapping struct {
	Canonical   string   `json:"canonical"`
	Aliases     []string `json:"aliases"`
	Description string   `json:"description"`
}

var fieldMappings = []FieldMapping{
	{Canonical: "source", Aliases: []string{"source"}, Description: "Leak source identifier"},
	{Canonical: "username", Aliases: []string{"username", "user", "login", "userid"}, Description: "Account username"},
	{Canonical: "firstname", Aliases: []string{"firstname", "first_name", "given_name", "forename"}, Description: "First name"},
	{Canonical: "lastname", Aliases: []string{"lastname", "last_name", "surname", "family_name"}, Description: "Last name"},
	{Canonical: "email", Aliases: []string{"email", "mail", "e_mail"}, Description: "Email address"},
	{Canonical: "phone", Aliases: []string{"phone", "phone_number", "mobile", "mobile_phone", "telephone", "tel"}, Description: "Phone number"},
	{Canonical: "password", Aliases: []string{"password", "pass", "pwd"}, Description: "Plain password"},
	{Canonical: "password_hash", Aliases: []string{"password_hash", "passhash", "hash"}, Description: "Password hash"},
	{Canonical: "ip", Aliases: []string{"ip", "ip_address"}, Description: "IP address"},
	{Canonical: "gender", Aliases: []string{"gender", "sex"}, Description: "Gender"},
	{Canonical: "address", Aliases: []string{"address", "addr"}, Description: "Address"},
	{Canonical: "birthday", Aliases: []string{"birthday", "birthdate", "date_of_birth", "dob"}, Description: "Birthday/date of birth"},
	{Canonical: "country", Aliases: []string{"country"}, Description: "Country"},
	{Canonical: "city", Aliases: []string{"city"}, Description: "City"},
	{Canonical: "created", Aliases: []string{"created", "created_at"}, Description: "Creation timestamp"},
	{Canonical: "updated", Aliases: []string{"updated", "updated_at"}, Description: "Update timestamp"},
	{Canonical: "marital_status", Aliases: []string{"marital_status"}, Description: "Marital status"},
	{Canonical: "title", Aliases: []string{"title", "job_title"}, Description: "Job title"},
	{Canonical: "linked_website", Aliases: []string{"linked_website", "website", "url", "domain"}, Description: "Linked website/domain"},
}

var aliasToCanonical = buildAliasToCanonicalMap(fieldMappings)

func CanonicalFieldMappings() []FieldMapping {
	out := make([]FieldMapping, len(fieldMappings))
	for i, mapping := range fieldMappings {
		aliasesCopy := make([]string, len(mapping.Aliases))
		copy(aliasesCopy, mapping.Aliases)
		out[i] = FieldMapping{
			Canonical:   mapping.Canonical,
			Aliases:     aliasesCopy,
			Description: mapping.Description,
		}
	}
	return out
}

func ResolveCanonicalField(input string) (string, bool) {
	value := normalizeMappingKey(input)
	canonical, ok := aliasToCanonical[value]
	return canonical, ok
}

func buildAliasToCanonicalMap(mappings []FieldMapping) map[string]string {
	out := make(map[string]string, len(mappings)*3)
	for _, mapping := range mappings {
		canonical := normalizeMappingKey(mapping.Canonical)
		if canonical == "" {
			continue
		}
		out[canonical] = mapping.Canonical
		for _, alias := range mapping.Aliases {
			normalizedAlias := normalizeMappingKey(alias)
			if normalizedAlias == "" {
				continue
			}
			out[normalizedAlias] = mapping.Canonical
		}
	}
	return out
}

func normalizeMappingKey(input string) string {
	key := strings.ToLower(strings.TrimSpace(input))
	key = strings.ReplaceAll(key, "-", "_")
	key = strings.ReplaceAll(key, " ", "_")
	key = strings.ReplaceAll(key, ".", "_")
	return key
}
