//go:build (linux && amd64) || darwin

package app

import (
	"fmt"
	"os"
	"os/user"
	"regexp"
	"strconv"
	"syscall"
)

// example function of using regexp to split lines in word tokens
func splitWithRegex() {
	s := "This is a,string: containing. whitespaces"

	t := regexp.MustCompile(`[ ,:@]+`) // backticks are used here to contain the expression

	v := t.Split(s, -1) // second arg -1 means no limits for the number of substrings
	for _, str := range v {
		fmt.Printf("[%s]\n", str) // [x zx zx zx zx z]
	}
}

func formatPermissions(mode os.FileMode) string {
	// Get permission bits
	perm := mode.Perm()

	// Construct permission string for user, group, others
	userPerm := permString(perm >> 6)
	groupPerm := permString(perm >> 3)
	othersPerm := permString(perm)

	// Check for special flags
	if mode&os.ModeSetuid != 0 {
		userPerm = setSpecialFlag(userPerm, 2, 'S', 's')
	}
	if mode&os.ModeSetgid != 0 {
		groupPerm = setSpecialFlag(groupPerm, 2, 'S', 's')
	}
	if mode&os.ModeSticky != 0 {
		othersPerm = setSpecialFlag(othersPerm, 2, 'T', 't')
	}

	return userPerm + groupPerm + othersPerm
}

func permString(perm os.FileMode) string {
	var r, w, x rune = '-', '-', '-'
	if perm&4 != 0 {
		r = 'r'
	}
	if perm&2 != 0 {
		w = 'w'
	}
	if perm&1 != 0 {
		x = 'x'
	}
	return string([]rune{r, w, x})
}

func setSpecialFlag(perm string, pos int, noExec, exec rune) string {
	runes := []rune(perm)
	if runes[pos] == 'x' {
		runes[pos] = exec
	} else {
		runes[pos] = noExec
	}
	return string(runes)
}

func printFileInfo(filePath string) string {
	// Extracting permission bits
	var ownerInfo *user.User
	var groupInfo *user.Group
	var userId, groupId int

	fileStat, err := os.Stat(filePath)

	if err != nil {
		return ""
	}

	if sysInfo, ok := fileStat.Sys().(*syscall.Stat_t); ok {
		userId = int(sysInfo.Uid)
		groupId = int(sysInfo.Gid)

		ownerInfo, _ = user.LookupId(strconv.Itoa(userId))
		groupInfo, _ = user.LookupGroupId(strconv.Itoa(groupId))
	}

	perm := formatPermissions(fileStat.Mode())
	if ownerInfo != nil || groupInfo != nil {
		return fmt.Sprintf("%v %8v %8v %v", perm, ownerInfo.Username, groupInfo.Name, filePath)
	} else {
		return fmt.Sprintf("%v %8v %8v %v", perm, userId, groupId, filePath)
	}
}
