package main

import (
	"log"
)

// sPlatformUpdaterActions are executed for S-Platform-Updater.
func sPlatformUpdaterActions() {
	// TODO: Complete this. For now we just drop into a shell.
	G.s.Execf("/bbin/elvish")
	//G.s.Execf("/bin/flashrom -p internal -r /tmp/dump")

	if err := G.s.Err(); err != nil {
		log.Printf("Script failed: %v", err)
		return
	}
}
