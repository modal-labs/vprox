package lib

import (
	"os"
	"path"
	"strings"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// RunDir is the path for runtime data that should be kept across restarts.
const RunDir string = "/run/vprox"

func createRunDir() error {
	return os.MkdirAll(RunDir, 0700)
}

func getKeyInternal(name string) (key wgtypes.Key, err error) {
	if err = createRunDir(); err != nil {
		return
	}
	keyFile := path.Join(RunDir, name)
	contents, err := os.ReadFile(keyFile)
	if os.IsNotExist(err) {
		// Generate a private key for the server. This private key will be reused in
		// event of a server restart, so we save it in `/run/vprox/key`.
		key, err = wgtypes.GeneratePrivateKey()
		if err != nil {
			return
		}
		if err = os.WriteFile(keyFile, []byte(key.String()), 0600); err != nil {
			return
		}
		return
	} else if err != nil {
		return
	}
	return wgtypes.ParseKey(strings.TrimSpace(string(contents)))
}

func GetServerKey() (key wgtypes.Key, err error) {
	return getKeyInternal("server-key")
}

func GetClientKey(ifname string) (key wgtypes.Key, err error) {
	return getKeyInternal("client-key-" + ifname)
}
