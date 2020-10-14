package custom

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"regexp"
)

type ChecksFile struct {
	Checks []CustomCheck `json:"checks"`
}

func init() {
	dir, err := os.UserHomeDir()
	if err != nil {
		return
	}
	customCheckDir := fmt.Sprintf("%s/.config/tfsec", dir)
	_, err = os.Stat(customCheckDir)
	if os.IsNotExist(err) {
		return
	}

	files, err := listFiles(customCheckDir, ".*_checks.json")
	if err != nil {
		return
	}
	for _, file := range files {
		checkJson, err := ioutil.ReadFile(path.Join(customCheckDir, file.Name()))
		if err != nil {
			continue
		}
		var checks ChecksFile
		err = json.Unmarshal(checkJson, &checks)
		if err != nil {
			continue
		}
		processFoundChecks(checks)
	}
}

func listFiles(dir, pattern string) ([]os.FileInfo, error) {
	files, err := ioutil.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	filteredFiles := []os.FileInfo{}
	for _, file := range files {
		if file.IsDir() {
			continue
		}
		matched, err := regexp.MatchString(pattern, file.Name())
		if err != nil {
			return nil, err
		}
		if matched {
			filteredFiles = append(filteredFiles, file)
		}
	}
	return filteredFiles, nil
}
