package utils

import (
	"fmt"
	"github.com/iancoleman/strcase"
	"reflect"
	"strings"
	"unicode"
)

// Options stores compliance check options.
type Options struct {
	Disabled           bool
	DisableTagPresent  bool
	DisableTagMismatch bool
}

// GetTagCompliance performs struct tag compliance checks.
func GetTagCompliance(resource interface{}, opts *Options) ([]string, error) {
	var output []string
	if opts == nil {
		opts = &Options{}
	}

	if opts.Disabled {
		return output, nil
	}

	rr := reflect.TypeOf(resource).Elem()
	//resourceType := fmt.Sprintf("%s", rr.Name())
	rk := fmt.Sprintf("%s", rr.Kind())

	if rk != "struct" {
		return nil, fmt.Errorf("resource kind %q is unsupported", rk)
	}

	suggestedStructChanges := []string{}

	requiredTags := []string{"json", "xml", "yaml"}
	for i := 0; i < rr.NumField(); i++ {
		resourceField := rr.Field(i)
		if !unicode.IsUpper(rune(resourceField.Name[0])) {
			// Skip internal fields.
			continue
		}

		expTagValue := convertFieldToTag(resourceField.Name)
		expTagValue = expTagValue + ",omitempty"
		var lastTag bool
		for j, tagName := range requiredTags {
			if len(requiredTags)-1 == j {
				lastTag = true
			}

			tagValue := resourceField.Tag.Get(tagName)

			if tagValue == "-" {
				continue
			}
			if tagValue == "" && !opts.DisableTagPresent {
				output = append(output, fmt.Sprintf(
					"tag %q not found in %s.%s (%v)",
					tagName,
					//resourceType,
					rr.Name(),
					resourceField.Name,
					resourceField.Type,
				))
				if lastTag {
					tags := makeTags(requiredTags, expTagValue)
					resType := fmt.Sprintf("%v", resourceField.Type)
					resType = strings.Replace(resType, "identity.", "", -1)
					suggestedStructChanges = append(suggestedStructChanges, fmt.Sprintf(
						"%s %s %s", resourceField.Name, resType, tags,
					))
				}
				continue
			}
			//if strings.Contains(tagValue, ",omitempty") {
			//	tagValue = strings.Replace(tagValue, ",omitempty", "", -1)
			//}
			if (tagValue != expTagValue) && !opts.DisableTagMismatch {
				output = append(output, fmt.Sprintf(
					"tag %q mismatch found in %s.%s (%v): %s (actual) vs. %s (expected)",
					tagName,
					//resourceType,
					rr.Name(),
					resourceField.Name,
					resourceField.Type,
					tagValue,
					expTagValue,
				))
				continue

			}
		}
	}

	if len(suggestedStructChanges) > 0 {
		output = append(output, fmt.Sprintf(
			"suggested struct changes to %s:\n%s",
			rr.Name(),
			strings.Join(suggestedStructChanges, "\n"),
		))
	}

	if len(output) > 0 {
		return output, fmt.Errorf("struct %q is not compliant", rr.Name())
	}

	return output, nil
}

func convertFieldToTag(s string) string {
	s = strcase.ToSnake(s)
	s = strings.ReplaceAll(s, "_md_5", "_md5")
	s = strings.ReplaceAll(s, "open_ssh", "openssh")
	return s
}

func makeTags(tags []string, s string) string {
	var b strings.Builder
	b.WriteRune('`')
	tagOutput := []string{}
	for _, tag := range tags {
		tagOutput = append(tagOutput, tag+":\""+s+"\"")
	}
	b.WriteString(strings.Join(tagOutput, " "))
	b.WriteRune('`')
	return b.String()
}