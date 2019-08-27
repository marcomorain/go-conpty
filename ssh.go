package ssh

import (
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"syscall"
	"unsafe"

	"github.com/pkg/errors"
	"golang.org/x/sys/windows"

	"github.com/gliderlabs/ssh"
)

var (
	// TODO: handle the error and unload the library properly.
	kernel32, _            = windows.LoadLibrary("kernel32.dll")
	createPseudoConsole, _ = windows.GetProcAddress(kernel32, "CreatePseudoConsole")
	resizePseudoConsole, _ = windows.GetProcAddress(kernel32, "ResizePseudoConsole")
	closePseudoConsole, _  = windows.GetProcAddress(kernel32, "ClosePseudoConsole")

	procCreateProcessW, _                = windows.GetProcAddress(kernel32, "CreateProcessW")
	initializeProcThreadAttributeList, _ = windows.GetProcAddress(kernel32, "InitializeProcThreadAttributeList")
	updateProcThreadAttribute, _         = windows.GetProcAddress(kernel32, "UpdateProcThreadAttribute")
)

// Size Defines the coordinates of a character cell in a console screen buffer
// The origin of the coordinate system (0,0) is at the top, left cell of the buffer.
// https://docs.microsoft.com/en-us/windows/console/coord-str
type Size struct {
	width  uint16
	height uint16
}

// PseudoConsole shut up linter
type PseudoConsole struct {
	pc windows.Handle

	// Close these after CreateProcess of child application with pseudoconsole object.
	inputReadSide   *os.File
	outputWriteSide *os.File

	// Hold onto these and use them for communication with the child through the pseudoconsole.
	InputWriteSide *os.File
	OutputReadSide *os.File
}

// Create foo
func Create(size Size) (*PseudoConsole, error) {
	var flags uint32
	var pc windows.Handle

	// Create pipes

	inputReadSide, inputWriteSide, err := os.Pipe()

	if err != nil {
		return nil, err
	}
	outputReadSide, outputWriteSide, err := os.Pipe()

	if err != nil {
		return nil, err
	}

	ret, _, err := syscall.Syscall6(
		uintptr(createPseudoConsole),
		5,
		uintptr(unsafe.Pointer(&size)),  // _In_ COORD size
		uintptr(inputReadSide.Fd()),     // _In_ HANDLE hInput
		uintptr(outputWriteSide.Fd()),   // _In_ HANDLE hOutput
		uintptr(unsafe.Pointer(&flags)), // _In_ DWORD dwFlags
		uintptr(unsafe.Pointer(&pc)),    // _Out_ HPCON* phPC
		0)

	fmt.Printf("CreatePseudoConsole width=%v height=%v ret=%x err=%v pc=%x\n", size.width, size.height, ret, err, pc)

	switch {
	case err != syscall.Errno(0):
		return nil, errors.Wrap(err, "failed to call CreatePseudoConsole Win32 API")

	default:
		return &PseudoConsole{pc: pc,
			inputReadSide:   inputReadSide,
			InputWriteSide:  inputWriteSide,
			OutputReadSide:  outputReadSide,
			outputWriteSide: outputWriteSide,
		}, nil
	}
}

// Resize lint lint
func (pc PseudoConsole) Resize(size Size) error {
	handle := pc.pc

	ret, _, err := syscall.Syscall(
		uintptr(resizePseudoConsole),
		2,
		uintptr(handle),                // _In_ HPCON hPC
		uintptr(unsafe.Pointer(&size)), // _In_ COORD size
		0)

	if ret != 0 {
		fmt.Printf("ResizePseudoConsole size=%v ret=%x err=%v\n", size, ret, err)
	}

	switch {
	case err != syscall.Errno(0):
		return errors.Wrap(err, "failed to call ResizePseudoConsole Win32 API")

	default:
		return nil
	}

}

// Close lint lint
func (pc PseudoConsole) Close() error {
	handle := pc.pc
	fmt.Printf("Close handle=%x\n", handle)

	ret, _, err := syscall.Syscall(uintptr(closePseudoConsole), 1, uintptr(handle), 0, 0) // _In_ HPCON hPC

	fmt.Printf("ClosePseudoConsole ret=%x err=%v\n", ret, err)

	pc.pc = windows.InvalidHandle

	// ret is 1 - what does this mean? It is 0 in the other system calls

	switch {
	// check for ret != OK
	case err != syscall.Errno(0):
		return errors.Wrap(err, "failed to call ClosePseudoConsole Win32 API")
	default:
		return nil
	}

}

func checkConsole() {
	size := Size{
		width:  100,
		height: 88,
	}
	console, err := Create(size)

	if err != nil {
		panic(err)
	}

	size.width = 108
	size.height = 90

	err = console.Resize(size)
	if err != nil {
		panic(err)
	}

	if err = console.Close(); err != nil {
		panic(err)
	}
}

func ptyStart(c *exec.Cmd, pc *PseudoConsole) error {

	// c.Stdout = pc.outputWriteSide
	// c.Stderr = pc.outputWriteSide
	// c.Stdin = pc.inputReadSide

	err := c.Start()

	if err != nil {
		return err
	}

	// if err = windows.CloseHandle(windows.Handle(pc.inputReadSide.Fd())); err != nil {
	// 	return err
	// }

	// if err = windows.CloseHandle(windows.Handle(pc.outputWriteSide.Fd())); err != nil {
	// 	return err
	// }

	return nil
}

// StartupInfoEx lint me
type StartupInfoEx struct {
	syscall.StartupInfo
	AttributeList *byte
}

func (pc PseudoConsole) bind(startupInfo *StartupInfoEx) error {

	// Initializes the specified startup info struct with the required properties and
	// updates its thread attribute list with the specified ConPTY handle

	startupInfo.StartupInfo.Cb = uint32(unsafe.Sizeof(*startupInfo))

	var attributeListSize int64

	ret, _, err := syscall.Syscall6(
		uintptr(initializeProcThreadAttributeList),
		4,
		uintptr(0),
		uintptr(1),
		uintptr(0),
		uintptr(unsafe.Pointer(&attributeListSize)),
		0,
		0)

	// windows.ERROR_INSUFFICIENT_BUFFER
	if ret != 0 {
		fmt.Printf("initializeProcThreadAttributeList ret=%x err=%v attrListsize=%v\n", ret, err, attributeListSize)
		return errors.Wrap(err, "first call failed")
	}
	var buffer = make([]byte, int(attributeListSize))
	startupInfo.AttributeList = &buffer[0]

	ret, _, err = syscall.Syscall6(
		uintptr(initializeProcThreadAttributeList),
		4,
		uintptr(unsafe.Pointer(startupInfo.AttributeList)),
		uintptr(1),
		uintptr(0),
		uintptr(unsafe.Pointer(&attributeListSize)),
		0,
		0)

	if ret != 1 {
		fmt.Printf("initializeProcThreadAttributeList ret=%x err=%v attrListsize=%v\n", ret, err, attributeListSize)
		return errors.Wrap(err, "second call failed")
	}

	// TODO - error check here

	var ProcThreadAttributePseudoconsole uint32 = 0x00020016

	ret, _, err = syscall.Syscall9(
		uintptr(updateProcThreadAttribute),
		7,
		uintptr(unsafe.Pointer(startupInfo.AttributeList)),
		uintptr(0),
		uintptr(ProcThreadAttributePseudoconsole),
		uintptr(pc.pc),
		uintptr(unsafe.Sizeof(pc.pc)),
		0,
		0,
		0,
		0)

	if ret != 1 {
		fmt.Printf("updateProcThreadAttribute ret=%x err=%v\n", ret, err)
	}

	return err
}

func runSSHServer(pc *PseudoConsole) {

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
func main() {

	defer windows.FreeLibrary(kernel32)

	// pc, err := Create(Size{width: 100, height: 100})

	// if err != nil {
	// 	panic(err)
	// }
	// monkey.Patch(syscall.CreateProcess,
	// 	func(appName *uint16, commandLine *uint16, procSecurity *syscall.SecurityAttributes, threadSecurity *syscall.SecurityAttributes, inheritHandles bool, creationFlags uint32, env *uint16, currentDir *uint16, startupInfo *syscall.StartupInfo, outProcInfo *syscall.ProcessInformation) (err error) {

	// 		fmt.Println("I hope you are proud, Marc")

	// 		var ExtendedStartupInfoPresent uint32 = 0x00080000
	// 		var startupInfoEx StartupInfoEx
	// 		startupInfoEx.StartupInfo = *startupInfo
	// 		// Don't sent in any pipes
	// 		creationFlags = creationFlags &^ windows.STARTF_USESTDHANDLES

	// 		pc.bind(&startupInfoEx)

	// 		//var extraCreateFlags uint32 = ExtendedStartupInfoPresent | windows.STARTF_USESHOWWINDOW
	// 		//startupInfoEx.ShowWindow = windows.SW_HIDE
	// 		//creationFlags = ExtendedStartupInfoPresent // creationFlags | extraCreateFlags

	// 		creationFlags = creationFlags | ExtendedStartupInfoPresent | windows.CREATE_UNICODE_ENVIRONMENT | windows.STARTF_USESHOWWINDOW | windows.STARTF_USESTDHANDLES

	// 		startupInfoEx.ShowWindow = windows.SW_HIDE

	// 		// startupInfoEx.StdInput = syscall.Handle(pc.InputWriteSide.Fd())
	// 		// startupInfoEx.StdOutput = syscall.Handle(pc.OutputReadSide.Fd())
	// 		// startupInfoEx.StdErr = syscall.Handle(pc.OutputReadSide.Fd())

	// 		startupInfoEx.StdInput = 0
	// 		startupInfoEx.StdOutput = 0
	// 		startupInfoEx.StdErr = 0
	// 		creationFlags = ExtendedStartupInfoPresent | windows.STARTF_USESHOWWINDOW

	// 		r1, _, e1 := syscall.Syscall12(procCreateProcessW,
	// 			10,
	// 			uintptr(unsafe.Pointer(appName)),
	// 			uintptr(unsafe.Pointer(commandLine)),
	// 			uintptr(0),
	// 			uintptr(0),
	// 			uintptr(0),
	// 			uintptr(creationFlags),
	// 			uintptr(0), //unsafe.Pointer(env)),
	// 			uintptr(0), // unsafe.Pointer(currentDir)),
	// 			uintptr(unsafe.Pointer(&startupInfoEx)),
	// 			uintptr(unsafe.Pointer(outProcInfo)),
	// 			0,
	// 			0)
	// 		if r1 == 0 {
	// 			if e1 != 0 {
	// 				err = e1
	// 			} else {
	// 				err = syscall.EINVAL
	// 			}
	// 		}

	// 		if err = windows.CloseHandle(windows.Handle(pc.inputReadSide.Fd())); err != nil {
	// 			return
	// 		}

	// 		if err = windows.CloseHandle(windows.Handle(pc.outputWriteSide.Fd())); err != nil {
	// 			return
	// 		}

	// 		return
	// 	})

	// // out, err := exec.Command("dir").Output()
	// // if err != nil {
	// // 	panic(err)
	// // }
	// // fmt.Println(string(out))

	// //checkConsole()
	// runSSHServer(pc)

}
