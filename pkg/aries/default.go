package aries

import (
	"os"
	"runtime"
)

const (
	DefaultPortTimeoutSynScan     = 1000
	DefaultPortTimeoutConnectScan = 2000

	DefaultRateSynScan     = 1000
	DefaultRateConnectScan = 1500

	DefaultRetriesSynScan     = 3
	DefaultRetriesConnectScan = 3

	SynScan             = "s"
	ConnectScan         = "c"
	DefautStatsInterval = 5
)

func isPrivileged() bool {
	return os.Geteuid() == 0 && isOSSupported()
}

func isOSSupported() bool {
	return isLinux() || isOSX()
}

func isOSX() bool {
	return runtime.GOOS == "darwin"
}

func isLinux() bool {
	return runtime.GOOS == "linux"
}

func isWindows() bool {
	return runtime.GOOS == "windows"
}
