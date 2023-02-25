//go:build darwin

package privilege

func isPrivileged() bool {
	return os.Geteuid() == 0
}
