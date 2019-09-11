package main

import (
	"fmt"
	"os"

	"github.com/marcomorain/go-win-py/pkg/pty"
)

func maina() {

	// TODO
	// defer windows.FreeLibrary(kernel32)

	if err := pty.EnableVirtualTerminalProcessing(); err != nil {
		fmt.Printf("enableVirtualTerminalProcessing failed %v\n", err)
		os.Exit(1)
	}

	fmt.Println("console is ok")
	// if err := pty.RunProcessWithPty(`ping localhost`); err != nil {
	// 	fmt.Printf("echo failed %v\n", err)
	// 	os.Exit(1)
	// }

}
