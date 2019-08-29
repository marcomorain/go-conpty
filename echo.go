package main

import (
	"fmt"
	"os"
	"syscall"
	"time"
	"unsafe"

	"github.com/pkg/errors"

	"golang.org/x/sys/windows"
)

var (
	// TODO: handle the error and unload the library properly.
	kernel32, _                          = windows.LoadLibrary("kernel32.dll")
	ClosePseudoConsole, _                = windows.GetProcAddress(kernel32, "ClosePseudoConsole")
	CreatePipe, _                        = windows.GetProcAddress(kernel32, "CreatePipe")
	CreateProcessW, _                    = windows.GetProcAddress(kernel32, "CreateProcessW")
	CreatePseudoConsole, _               = windows.GetProcAddress(kernel32, "CreatePseudoConsole")
	DeleteProcThreadAttributeList, _     = windows.GetProcAddress(kernel32, "DeleteProcThreadAttributeList")
	GetConsoleMode, _                    = windows.GetProcAddress(kernel32, "GetConsoleMode")
	GetConsoleScreenBufferInfo, _        = windows.GetProcAddress(kernel32, "GetConsoleScreenBufferInfo")
	GetStdHandle, _                      = windows.GetProcAddress(kernel32, "GetStdHandle")
	InitializeProcThreadAttributeList, _ = windows.GetProcAddress(kernel32, "InitializeProcThreadAttributeList")
	ReadFile, _                          = windows.GetProcAddress(kernel32, "ReadFile")
	ResizePseudoConsole, _               = windows.GetProcAddress(kernel32, "ResizePseudoConsole")
	SetConsoleMode, _                    = windows.GetProcAddress(kernel32, "SetConsoleMode")
	UpdateProcThreadAttribute, _         = windows.GetProcAddress(kernel32, "UpdateProcThreadAttribute")
	WaitForSingleObject, _               = windows.GetProcAddress(kernel32, "WaitForSingleObject")
	WriteFile, _                         = windows.GetProcAddress(kernel32, "WriteFile")
)

type Dword uint32

// EnableVirtualTerminalProcessing Enable Console VT Processing
func enableVirtualTerminalProcessing() error {

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

type Word uint16
type Short int16

// Coord Size
type Coord struct {
	X uint16
	Y uint16
}

type SmallRect struct {
	Left   Short
	Top    Short
	Right  Short
	Bottom Short
}

type ConsoleScreenBufferInfo struct {
	dwSize              Coord
	dwCursorPosition    Coord
	wAttributes         Word
	srWindow            SmallRect
	dwMaximumWindowSize Coord
}

// StartupInfoEx lint me
type StartupInfoEx struct {
	windows.StartupInfo
	AttributeList *byte
}

func win32Bool(r1, r2 uintptr, err error) error {
	switch {
	case err != syscall.Errno(0):
		return err

	case r1 == 0:
		return fmt.Errorf("bool Win32 syscall failed: r1=%X r2=%X err=%v", r1, r2, err)
	default:
		return nil
	}
}

func win32Hresult(r1, r2 uintptr, err error) error {
	switch {
	case err != syscall.Errno(0):
		return err

	case r1 != 0:
		return fmt.Errorf("hresult Win32 syscall faild: r1=%X r2=%X err=%v", r1, r2, err)
	default:
		return nil
	}
}

func win32Void(r1, r2 uintptr, err error) error {
	if err != syscall.Errno(0) {
		return err
	}
	return nil
}

func getScreenSize() (size *Coord, err error) {
	// Determine required size of Pseudo Console
	var consoleSize = new(Coord)
	var csbi windows.ConsoleScreenBufferInfo

	console, err := windows.GetStdHandle(windows.STD_OUTPUT_HANDLE)

	if err != nil {
		return nil, err
	}

	err = windows.GetConsoleScreenBufferInfo(console, &csbi)

	if err != nil {
		return nil, err
	}

	consoleSize.X = uint16(csbi.Window.Right - csbi.Window.Left + 1)
	consoleSize.Y = uint16(csbi.Window.Bottom - csbi.Window.Top + 1)

	return consoleSize, nil
}

func createPipes() (read, write windows.Handle, err error) {
	err = windows.CreatePipe(&read, &write, nil, 0)
	return
}

func createPseudoConsoleAndPipes() (pc, pipeIn, pipeOut windows.Handle, err error) {

	pipePtyIn, pipeOut, err := createPipes()
	if err != nil {
		return
	}

	pipeIn, pipePtyOut, err := createPipes()
	if err != nil {
		return
	}

	size, err := getScreenSize()
	if err != nil {
		return
	}

	err = win32Hresult(syscall.Syscall6(
		CreatePseudoConsole,
		5,
		uintptr(unsafe.Pointer(&size)), // _In_ COORD size
		uintptr(pipePtyIn),             // _In_ HANDLE hInput
		uintptr(pipePtyOut),            // _In_ HANDLE hOutput
		0,
		uintptr(unsafe.Pointer(&pc)), // _Out_ HPCON* phPC
		0))

	_ = windows.CloseHandle(pipePtyIn)
	_ = windows.CloseHandle(pipePtyOut)

	return
}

// Initializes the specified startup info struct with the required properties and
// updates its thread attribute list with the specified ConPTY handle
func InitializeStartupInfoAttachedToPseudoConsole(pc windows.Handle) (*StartupInfoEx, []byte, error) {

	startupInfo := new(StartupInfoEx)
	startupInfo.StartupInfo.Cb = uint32(unsafe.Sizeof(*startupInfo))

	var attributeListSize int64

	ret, _, err := syscall.Syscall6(InitializeProcThreadAttributeList, 4,
		0, 1, 0, uintptr(unsafe.Pointer(&attributeListSize)), 0, 0)

	if err != windows.ERROR_INSUFFICIENT_BUFFER {
		return nil, nil, errors.Wrap(err, "Failed to compute attribute list size")
	}

	if ret != 0 {
		return nil, nil, fmt.Errorf("initializeProcThreadAttributeList ret=%x err=%v attrListsize=%v", ret, err, attributeListSize)
	}

	var buffer = make([]byte, int(attributeListSize))
	startupInfo.AttributeList = &buffer[0]

	e1 := win32Bool(syscall.Syscall6(InitializeProcThreadAttributeList, 4,
		uintptr(unsafe.Pointer(startupInfo.AttributeList)), 1, 0, uintptr(unsafe.Pointer(&attributeListSize)), 0, 0))

	if e1 != nil {
		return nil, nil, errors.Wrap(e1, "Failed InitializeProcThreadAttributeList")
	}

	var ProcThreadAttributePseudoconsole uint32 = 0x00020016

	e2 := win32Bool(syscall.Syscall9(
		UpdateProcThreadAttribute,
		7,
		uintptr(unsafe.Pointer(startupInfo.AttributeList)),
		0,
		uintptr(ProcThreadAttributePseudoconsole),
		uintptr(pc),
		uintptr(unsafe.Sizeof(pc)),
		0,
		0,
		0,
		0))

	return startupInfo, buffer, errors.Wrap(e2, "Failed UpdateProcThreadAttribute")
}

func echo() error {
	szCommand := "ping localhost"

	pc, pipeIn, pipeOut, err := createPseudoConsoleAndPipes()

	if err != nil {
		return errors.Wrap(err, "failed to create pipes")
	}

	// Create & start thread to listen to the incoming pipe
	go PipeListener(pipeIn)

	startupInfo, _, err := InitializeStartupInfoAttachedToPseudoConsole(pc)

	if err != nil {
		return errors.Wrap(err, "failed to InitializeStartupInfoAttachedToPseudoConsole")
	}

	var piClient windows.ProcessInformation

	err = windows.CreateProcess(nil, syscall.StringToUTF16Ptr(szCommand), nil, nil, false, windows.EXTENDED_STARTUPINFO_PRESENT, nil, nil, &startupInfo.StartupInfo, &piClient)

	if err != nil {
		return errors.Wrap(err, "Create process failed")
	}

	// Wait up to 10s for ping process to complete
	err = win32Hresult(syscall.Syscall(WaitForSingleObject, 2, uintptr(piClient.Thread), 10*1000, 0))
	if err != nil {
		return errors.Wrap(err, "WaitForSingleObjectd")
	}

	// Allow listening thread to catch-up with final output!
	//		Sleep(500);
	time.Sleep(500 * time.Millisecond)

	// --- CLOSEDOWN ---
	// Now safe to clean-up client app's process-info & thread

	_ = windows.CloseHandle(windows.Handle(piClient.Thread))
	_ = windows.CloseHandle(windows.Handle(piClient.Process))

	// Cleanup attribute list

	err = win32Void(syscall.Syscall(DeleteProcThreadAttributeList, 1, uintptr(unsafe.Pointer(startupInfo.AttributeList)), 0, 0))

	if err != nil {
		return errors.Wrap(err, "DeleteProcThreadAttributeList")
	}

	// free(startupInfo.lpAttributeList); This is GCed by golang

	// Close ConPTY - this will terminate client process if running

	err = win32Void(syscall.Syscall(ClosePseudoConsole, 1, uintptr(pc), 0, 0)) // _In_ HPCON hPC

	if err != nil {
		return errors.Wrap(err, "ClosePseudoConsole")
	}

	// Clean-up the pipes

	_ = windows.CloseHandle(pipeOut)
	//_ = closeThisHandle(pipeIn) // done in IO goroutine

	return nil

}

func PipeListener(pipe windows.Handle) {

	console, err := windows.GetStdHandle(windows.STD_OUTPUT_HANDLE)

	if err != nil {
		panic(err) // TODO: error channel
	}

	const buffSize = 512

	szBuffer := make([]byte, buffSize)

	for {
		// Read from the pipe
		var bytesRead uint32
		_ = windows.ReadFile(pipe, szBuffer, &bytesRead, nil) // todo error checking

		// if err != nil {
		// 	panic(err)
		// }

		var bytesWritten uint32
		_ = windows.WriteFile(console, szBuffer[:bytesRead], &bytesWritten, nil) // todo error checking

		// if err != nil {
		// 	panic(err)
		// }

		if bytesRead < 1 {
			break
		}
	}

	_ = windows.CloseHandle(pipe) // todo handle error
}

func main() {
	if err := enableVirtualTerminalProcessing(); err != nil {
		fmt.Printf("enableVirtualTerminalProcessing failed %v\n", err)
		os.Exit(1)

	}
	if err := echo(); err != nil {
		fmt.Printf("echo failed %v\n", err)
		os.Exit(1)
	}

}
