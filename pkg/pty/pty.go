package pty

import (
	"encoding/json"
	"fmt"
	"syscall"
	"time"
	"unsafe"

	"github.com/pkg/errors"

	"github.com/davecgh/go-spew/spew"
	"golang.org/x/sys/windows"
)

var (
	// TODO: handle the error and unload the library properly.
	kernel32, _                          = windows.LoadLibrary("kernel32.dll")
	closePseudoConsole, _                = windows.GetProcAddress(kernel32, "ClosePseudoConsole")
	createPseudoConsole, _               = windows.GetProcAddress(kernel32, "CreatePseudoConsole")
	deleteProcThreadAttributeList, _     = windows.GetProcAddress(kernel32, "DeleteProcThreadAttributeList")
	initializeProcThreadAttributeList, _ = windows.GetProcAddress(kernel32, "InitializeProcThreadAttributeList")
	resizePseudoConsole, _               = windows.GetProcAddress(kernel32, "ResizePseudoConsole")
	updateProcThreadAttribute, _         = windows.GetProcAddress(kernel32, "UpdateProcThreadAttribute")
)

func PrettyPrint(data interface{}) {
	var p []byte
	//    var err := error
	p, err := json.MarshalIndent(data, "", "\t")
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("%s \n", p)
}

// EnableVirtualTerminalProcessing Enable Console VT Processing
func EnableVirtualTerminalProcessing() error {

	console, err := windows.GetStdHandle(windows.STD_OUTPUT_HANDLE)

	if err != nil {
		return errors.Wrap(err, "Failed to get a handle to stdout")
	}

	var consoleMode uint32
	err = windows.GetConsoleMode(console, &consoleMode)

	if err != nil {
		return errors.Wrap(err, "GetConsoleMode")
	}

	err = windows.SetConsoleMode(console, consoleMode|windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING)

	return errors.Wrap(err, "SetConsoleMode")
}

// StartupInfoEx lint me
type StartupInfoEx struct {
	windows.StartupInfo
	AttributeList *byte
}

func win32Bool(r1, r2 uintptr, err error) error {
	//fmt.Printf("bool Win32 syscall: r1=%X r2=%X err=%v\n", r1, r2, err)

	switch {
	case err != windows.Errno(0):
		return err

	case r1 == 0:
		return fmt.Errorf("bool Win32 syscall failed: r1=%X r2=%X err=%v", r1, r2, err)
	default:
		return nil
	}
}

func win32Hresult(r1, r2 uintptr, err error) error {
	//fmt.Printf("win32Hresult: r1=%X r2=%X err=%v\n", r1, r2, err)

	switch {
	case err != windows.Errno(0):
		return err

	case r1 != 0:
		return fmt.Errorf("hresult Win32 syscall faild: r1=%X r2=%X err=%v", r1, r2, err)
	default:
		return nil
	}
}

func win32Void(r1, r2 uintptr, err error) error {
	//fmt.Printf("win32Void: r1=%x r2=%x err=%v\n", r1, r2, err)
	if err != windows.Errno(0) {
		return err
	}
	return nil
}

func getScreenSize() (size *windows.Coord, err error) {
	// Determine required size of Pseudo Console
	var consoleSize = new(windows.Coord)
	var csbi windows.ConsoleScreenBufferInfo

	console, err := windows.GetStdHandle(windows.STD_OUTPUT_HANDLE)

	if err != nil {
		return nil, err
	}

	err = windows.GetConsoleScreenBufferInfo(console, &csbi)

	if err != nil {
		return nil, err
	}

	consoleSize.X = csbi.Window.Right - csbi.Window.Left + 1
	consoleSize.Y = csbi.Window.Bottom - csbi.Window.Top + 1

	return consoleSize, nil
}

func createPipes() (read, write windows.Handle, err error) {
	err = windows.CreatePipe(&read, &write, nil, 0)
	return
}

func createPseudoConsoleAndPipes() (pc, pipeIn, pipeOut windows.Handle, err error) {

	pipePtyIn, pipeOut, err := createPipes()
	if err != nil {
		return 0, 0, 0, errors.Wrap(err, "failed to create pipePtyIn pipe")
	}

	defer windows.CloseHandle(pipePtyIn)

	pipeIn, pipePtyOut, err := createPipes()
	if err != nil {
		return 0, 0, 0, errors.Wrap(err, "failed to create pipePtyOut pipe")
	}

	defer windows.CloseHandle(pipePtyOut)

	size, err := getScreenSize() // TODO: pass this is
	if err != nil {
		return 0, 0, 0, errors.Wrap(err, "failed to read screen size")
	}

	fmt.Printf("Screen: %v %v\n", size.X, size.Y)

	err = win32Hresult(syscall.Syscall6(
		createPseudoConsole,
		5,
		uintptr(unsafe.Pointer(&size)), // _In_ COORD size
		uintptr(pipePtyIn),             // _In_ HANDLE hInput
		uintptr(pipePtyOut),            // _In_ HANDLE hOutput
		0,
		uintptr(unsafe.Pointer(&pc)), // _Out_ HPCON* phPC
		0))

	if err != nil {
		return 0, 0, 0, errors.Wrap(err, "CreatePseudoConsole failed")
	}
	return pc, pipeIn, pipeOut, nil
}

// Resize lint lint
func Resize(pc windows.Handle, size windows.Coord) error {
	return win32Hresult(syscall.Syscall(
		resizePseudoConsole,
		2,
		uintptr(pc),                    // _In_ HPCON hPC
		uintptr(unsafe.Pointer(&size)), // _In_ COORD size
		0))
}

type GoStartupInfo struct {
	si     StartupInfoEx
	buffer []byte
}

// InitializeStartupInfoAttachedToPseudoConsole Initializes the specified startup info
// struct with the required properties and updates its thread attribute list with the
// specified ConPTY handle
func InitializeStartupInfoAttachedToPseudoConsole(pc windows.Handle) (*GoStartupInfo, error) {

	if pc == windows.InvalidHandle {
		return nil, errors.New("bad pc")
	}

	startupInfo := new(GoStartupInfo)

	startupInfo.si.Cb = uint32(unsafe.Sizeof(startupInfo.si))

	var attributeListSize int64

	ret, _, err := syscall.Syscall6(initializeProcThreadAttributeList, 4,
		0, 1, 0, uintptr(unsafe.Pointer(&attributeListSize)), 0, 0)

	if err != windows.ERROR_INSUFFICIENT_BUFFER {
		return nil, errors.Wrap(err, "Failed to compute attribute list size")
	}

	if ret != 0 {
		return nil, fmt.Errorf("initializeProcThreadAttributeList ret=%x err=%v attrListsize=%v", ret, err, attributeListSize)
	}

	startupInfo.buffer = make([]byte, int(attributeListSize))
	startupInfo.si.AttributeList = &startupInfo.buffer[0]

	e1 := win32Bool(syscall.Syscall6(initializeProcThreadAttributeList, 4,
		uintptr(unsafe.Pointer(startupInfo.si.AttributeList)), 1, 0, uintptr(unsafe.Pointer(&attributeListSize)), 0, 0))

	if e1 != nil {
		return nil, errors.Wrap(e1, "Failed InitializeProcThreadAttributeList")
	}

	var ProcThreadAttributePseudoconsole uint32 = 0x00020016

	PrettyPrint(startupInfo)

	e2 := win32Bool(syscall.Syscall9(
		updateProcThreadAttribute,
		7,
		uintptr(unsafe.Pointer(startupInfo.si.AttributeList)),
		0,
		uintptr(ProcThreadAttributePseudoconsole),
		uintptr(pc),
		uintptr(unsafe.Sizeof(pc)),
		0,
		0,
		0,
		0))

	return startupInfo, errors.Wrap(e2, "Failed UpdateProcThreadAttribute")
}

func copy(dst, src windows.Handle, side string) (written int64, err error) {
	buffer := make([]byte, 1024)
	written = 0

	for {
		// Read from the pipe
		var bytesRead uint32
		err = windows.ReadFile(src, buffer, &bytesRead, nil)

		if err != nil || bytesRead == 0 {
			//fmt.Printf("%s: closing after read bytesRead: %d written: %d err: %v\n", side, bytesRead, written, err)
			return
		}

		var bytesWritten uint32
		err = windows.WriteFile(dst, buffer[:bytesRead], &bytesWritten, nil)

		if err != nil {
			//fmt.Printf("%s: closing after write bytesWritten: %d written: %d err: %v\n", side, bytesWritten, written, err)
			return
		}

		written += int64(bytesWritten)

	}
}

// Echo test entry point
func RunProcessWithPty(command string) error {

	pc, pipeIn, pipeOut, err := createPseudoConsoleAndPipes()

	if err != nil {
		return errors.Wrap(err, "failed to create pipes")
	}

	//fmt.Printf("pc is %x\n", pc)

	// Clean-up the pipes
	defer windows.CloseHandle(pipeOut)
	defer windows.CloseHandle(pipeIn)

	console, err := windows.GetStdHandle(windows.STD_OUTPUT_HANDLE)

	if err != nil {
		return err
	}

	stdin, err := windows.GetStdHandle(windows.STD_INPUT_HANDLE)

	startupInfo, err := InitializeStartupInfoAttachedToPseudoConsole(pc)

	if err != nil {
		return errors.Wrap(err, "failed to InitializeStartupInfoAttachedToPseudoConsole")
	}

	var procInfo windows.ProcessInformation

	var flags uint32 = windows.EXTENDED_STARTUPINFO_PRESENT

	commandLine := windows.StringToUTF16Ptr(command)

	inheritHandles := false

	spew.Dump(startupInfo)

	err = windows.CreateProcess(nil, commandLine, nil, nil, inheritHandles,
		flags,
		nil, nil, &(startupInfo.si.StartupInfo), &procInfo)

	fmt.Println("process created")
	if err != nil {
		return errors.Wrap(err, "Create process failed")
	}

	defer windows.CloseHandle(procInfo.Thread)
	defer windows.CloseHandle(procInfo.Process)
	defer ClosePseudoConsole(pc)

	//fmt.Printf("Process: %v %v Thread: %v %v\n", piClient.ProcessId, piClient.Process, piClient.ThreadId, piClient.Thread)

	// Create & start thread to listen to the incoming pipe
	go copy(console, pipeIn, "to stdout")
	go copy(pipeOut, stdin, "from stdin")

	// Wait up to 10s for ping process to complete
	event, err := windows.WaitForSingleObject(procInfo.Process, 10*1000)
	if err != nil {
		return errors.Wrap(err, "WaitForSingleObjectd")
	}

	if event != 0 {
		return fmt.Errorf("WaitForSingleObject returned event %x", event)
	}
	//fmt.Printf("waited ok: %x\n", event)

	var exitCode uint32
	windows.GetExitCodeProcess(procInfo.Process, &exitCode)

	if exitCode != 0 {
		return fmt.Errorf("exit process code: %x", exitCode)
	}

	// Allow listening thread to catch-up with final output!
	time.Sleep(500 * time.Millisecond)

	//fmt.Printf("slept ok buffer is %v\n", buffer)

	// --- CLOSEDOWN ---
	// Now safe to clean-up client app's process-info & thread

	fmt.Println("Handles closed ok")

	// Cleanup attribute list

	err = win32Void(syscall.Syscall(deleteProcThreadAttributeList, 1, uintptr(unsafe.Pointer(startupInfo.si.AttributeList)), 0, 0))

	if err != nil {
		return errors.Wrap(err, "DeleteProcThreadAttributeList")
	}

	// free(startupInfo.lpAttributeList); This is GCed by golang

	return nil

}

func ClosePseudoConsole(pc windows.Handle) error {
	// Close ConPTY - this will terminate client process if running
	fmt.Printf("Closing console %v\n", pc)
	err := win32Void(syscall.Syscall(closePseudoConsole, 1, uintptr(pc), 0, 0)) // _In_ HPCON hPC
	err = errors.Wrap(err, "Failed to close PseudoConsole")
	if err != nil {
		fmt.Printf("Error: %s\n", err)
	}
	return err
}
