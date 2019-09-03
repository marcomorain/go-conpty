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

	if err := pty.RunProcessWithPty(`ping localhost`, os.Stdin, os.Stdout); err != nil {
		fmt.Printf("echo failed %v\n", err)
		os.Exit(1)
	}

}
