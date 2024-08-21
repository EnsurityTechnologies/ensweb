package ensweb

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"

	homedir "github.com/mitchellh/go-homedir"
	"github.com/natefinch/atomic"
)

var _ TokenHelper = (*InternalTokenHelper)(nil)

type InternalTokenHelper struct {
	accessTokenPath  string
	refreshTokenPath string
	homeDir          string
	accessFileName   string
	refreshFileName  string
}

func NewInternalTokenHelper(dir string, accessFileName string, refreshFileName string) (*InternalTokenHelper, error) {
	homeDir := dir
	if homeDir == "" {
		var err error
		homeDir, err = homedir.Dir()
		if err != nil {
			return nil, err
		}
	}
	ifh := &InternalTokenHelper{
		homeDir:          homeDir,
		accessFileName:   accessFileName,
		refreshFileName:  refreshFileName,
		accessTokenPath:  filepath.Join(homeDir, accessFileName),
		refreshTokenPath: filepath.Join(homeDir, refreshFileName),
	}
	return ifh, nil
}

func (i *InternalTokenHelper) GetAccessToken() (string, error) {
	f, err := os.Open(i.accessTokenPath)
	if os.IsNotExist(err) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	defer f.Close()

	buf := bytes.NewBuffer(nil)
	if _, err := io.Copy(buf, f); err != nil {
		return "", err
	}

	return strings.TrimSpace(buf.String()), nil
}

func (i *InternalTokenHelper) StoreAccessToken(input string) error {
	tmpFile := i.accessTokenPath + ".tmp"
	f, err := os.OpenFile(tmpFile, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	defer os.Remove(tmpFile)

	_, err = io.WriteString(f, input)
	if err != nil {
		return err
	}
	err = f.Close()
	if err != nil {
		return err
	}
	return atomic.ReplaceFile(tmpFile, i.accessTokenPath)
}

func (i *InternalTokenHelper) GetRefreshToken() (string, error) {
	f, err := os.Open(i.refreshTokenPath)
	if os.IsNotExist(err) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	defer f.Close()

	buf := bytes.NewBuffer(nil)
	if _, err := io.Copy(buf, f); err != nil {
		return "", err
	}

	return strings.TrimSpace(buf.String()), nil
}

func (i *InternalTokenHelper) StoreRefreshToken(input string) error {
	tmpFile := i.refreshTokenPath + ".tmp"
	f, err := os.OpenFile(tmpFile, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	defer os.Remove(tmpFile)

	_, err = io.WriteString(f, input)
	if err != nil {
		return err
	}
	err = f.Close()
	if err != nil {
		return err
	}
	return atomic.ReplaceFile(tmpFile, i.refreshTokenPath)
}

func (i *InternalTokenHelper) Erase() error {
	if err := os.Remove(i.accessTokenPath); err != nil && !os.IsNotExist(err) {
		return err
	}
	if err := os.Remove(i.refreshTokenPath); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}
