package scan

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/zan8in/gologger"
	"github.com/zan8in/pavo"
)

func (s *Scanner) PavoPortScan(ip string, size int) (pavo.Results, error) {
	if !pavo.IsFofa() {
		err := fmt.Errorf("missing fofa email and key, please edit file `%s`", s.PavoConfigName())
		gologger.Info().Msg(err.Error())
		return pavo.Results{}, err
	}

	return pavo.QueryIPPort(ip, size)
}

func (s *Scanner) PavoConfigName() string {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return ""
	}

	configDir := filepath.Join(homeDir, ".config", "pavo")

	return filepath.Join(configDir, "pavo.yml")
}
