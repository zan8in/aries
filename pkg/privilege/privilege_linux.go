//go:build linux || unix

package privilege

func isPrivileged() bool {
	return os.Geteuid() == 0
}
