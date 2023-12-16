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

func printFileInfo(filePath string) string {
	// Extracting permission bits
	var ownerInfo *user.User
	var groupInfo *user.Group

	fileStat, err := os.Stat(filePath)

	if err != nil {
		return ""
	}

	if sysInfo, ok := fileStat.Sys().(*syscall.Stat_t); ok {
		userId := int(sysInfo.Uid)
		groupId := int(sysInfo.Gid)

		ownerInfo, err = user.LookupId(strconv.Itoa(userId))
		if err != nil {
			fmt.Println("Error:", err)
		}
		groupInfo, err = user.LookupGroupId(strconv.Itoa(groupId))
		if err != nil {
			fmt.Println("Error:", err)
		}
	}

	if ownerInfo != nil && groupInfo != nil {
		perm := fileStat.Mode().Perm()

		// Mimic `ls -l` format: permissions, owner, group, filename
		return fmt.Sprintf("%v %8v %8v %v", perm, ownerInfo.Username, groupInfo.Name, filePath)
	}
	return ""
}
