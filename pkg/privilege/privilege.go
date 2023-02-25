package privilege

var IsPrivileged bool

func init() {
	IsPrivileged = isPrivileged()
}
