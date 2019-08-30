package main

import (
	"fmt"
	"os"
	"runtime/debug"

	"github.com/marcomorain/go-win-py/pkg/pty"
)

/*
func runSSHServer(pc windows.Handle) {

	ssh.Handle(func(session ssh.Session) {
		io.WriteString(session, "Called ssh.Handle\n")

		ptyReq, winCh, isPty := session.Pty()

		fmt.Printf("session: is PTY=%v window (%v,%v)\n", isPty, ptyReq.Window.Width, ptyReq.Window.Height)

		command := session.Command()

		if !isPty && len(command) == 0 {
			fmt.Fprintf(session, "Error: %s\n", "No command or PTY requested")
			session.Exit(1)
			return
		}

		var cmd *exec.Cmd
		if len(command) == 0 {
			cmd = exec.Command("dir.exe") //"cmd.exe")
		} else {
			cmd = exec.Command(command[0], command[1:]...)
		}

		// pc.Resize(Size{
		// 	width:  uint16(ptyReq.Window.Width),
		// 	height: uint16(ptyReq.Window.Height),
		// })

		err := ptyStart(cmd, pc)
		if err != nil {
			fmt.Fprintf(session, "Error: %s\n", err)
			session.Exit(1)
			return
		}

		go func() {
			for win := range winCh {

				fmt.Printf("Received resize event for PTY: %v\n", win)
				pc.Resize(Size{
					width:  uint16(win.Width),
					height: uint16(win.Height),
				})
			}
		}()
		go func() {
			written, err := io.Copy(pc.InputWriteSide, session) // stdin
			fmt.Printf("io.Copy stdin %v written: %v\n", written, err)
		}()

		written, err := io.Copy(session, pc.OutputReadSide) // stdout
		fmt.Printf("Read all of the stdout output - %v bytes written: err = %v\n", written, err)
		fmt.Printf("Waiting for process to complete\n")

		err = cmd.Wait()
		fmt.Printf("Waited for process exit: %s %X\n", cmd.ProcessState.String(), cmd.ProcessState.ExitCode())
	})

	log.Fatal(ssh.ListenAndServe(":2222", nil))

}

// pc, err := Create(Size{width: 100, height: 100})

// if err != nil {
// 	panic(err)
// }

// // out, err := exec.Command("dir").Output()
// // if err != nil {
// // 	panic(err)
// // }
// // fmt.Println(string(out))

// //checkConsole()
// runSSHServer(pc)

*/
func main() {

	debug.SetGCPercent(-1)

	// TODO
	// defer windows.FreeLibrary(kernel32)

	if err := pty.EnableVirtualTerminalProcessing(); err != nil {
		fmt.Printf("enableVirtualTerminalProcessing failed %v\n", err)
		os.Exit(1)
	}

	fmt.Println("console is ok")
	if err := pty.RunProcessWithPty("powershell.exe"); err != nil {
		fmt.Printf("echo failed %v\n", err)
		os.Exit(1)
	}

}
