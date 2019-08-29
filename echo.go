package main

import (
	"encoding/json"
	"fmt"
	"os"
	"syscall"
	"time"
	"unicode/utf16"
	"unsafe"

	"github.com/pkg/errors"

	"golang.org/x/sys/windows"
)

var (
	// TODO: handle the error and unload the library properly.
	kernel32, _                          = windows.LoadLibrary("kernel32.dll")
	CloseHandle, _                       = windows.GetProcAddress(kernel32, "CloseHandle")
	ClosePseudoConsole, _                = windows.GetProcAddress(kernel32, "ClosePseudoConsole")
	CreatePipe, _                        = windows.GetProcAddress(kernel32, "CreatePipe")
	CreateProcessA, _                    = windows.GetProcAddress(kernel32, "CreateProcessA")
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

func prettyPrint(data interface{}) {
	var p []byte
	//    var err := error
	p, err := json.MarshalIndent(data, "", "\t")
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("%s \n", p)
}

type Dword uint32

func getStdOut() (uintptr, error) {
	console, _, err := syscall.Syscall(GetStdHandle, 1, windows.STD_OUTPUT_HANDLE, 0, 0)

	if err != syscall.Errno(0) {
		return 0, err
	}

	return console, nil
}

// EnableVirtualTerminalProcessing Enable Console VT Processing
func enableVirtualTerminalProcessing() error {
	console, err := getStdOut()

	if err != nil {
		return errors.Wrap(err, "Failed to get a handle to stdout")
	}

	var consoleMode Dword
	result, _, err := syscall.Syscall(GetConsoleMode, 2, console, uintptr(unsafe.Pointer(&consoleMode)), 0)

	if err != syscall.Errno(0) {
		return errors.Wrap(err, "GetConsoleMode")
	}

	if result == 0 {
		return errors.New("GetConsoleMode failed")
	}

	result, _, err = syscall.Syscall(SetConsoleMode, 2, console, uintptr(consoleMode|windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING), 0)

	if err != syscall.Errno(0) {
		return errors.Wrap(err, "SetConsoleMode")
	}

	if result == 0 {
		return errors.New("SetConsoleMode failed")
	}

	return nil
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
	syscall.StartupInfo
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
	switch {
	case err != syscall.Errno(0):
		return err

	case r1 != 0:
		return fmt.Errorf("void Win32 syscall faild: r1=%X r2=%X err=%v", r1, r2, err)
	default:
		return nil
	}
}

func getScreenSize() (size *Coord, err error) {
	// Determine required size of Pseudo Console
	var consoleSize = new(Coord)
	var csbi ConsoleScreenBufferInfo

	console, err := getStdOut()

	if err != nil {
		return nil, err
	}

	err = win32Bool(syscall.Syscall(GetConsoleScreenBufferInfo, 2, console, uintptr(unsafe.Pointer(&csbi)), 0))

	// TODO: error checking

	consoleSize.X = uint16(csbi.srWindow.Right - csbi.srWindow.Left + 1)
	consoleSize.Y = uint16(csbi.srWindow.Bottom - csbi.srWindow.Top + 1)

	return consoleSize, nil
}

func createPipes() (read, write windows.Handle, err error) {
	read, write = windows.InvalidHandle, windows.InvalidHandle
	err = win32Bool(syscall.Syscall6(CreatePipe, 4, uintptr(unsafe.Pointer(&read)), uintptr(unsafe.Pointer(&write)), 0, 0, 0, 0))
	return
}

func closeThisHandle(h windows.Handle) error {
	if h == windows.InvalidHandle {
		return nil
	}
	return win32Bool(syscall.Syscall(CloseHandle, 1, uintptr(h), 0, 0))
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

	_ = closeThisHandle(pipePtyIn)
	_ = closeThisHandle(pipePtyIn)

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

	// windows.ERROR_INSUFFICIENT_BUFFER
	// TODO: check for windows.ERROR_INSUFFICIENT_BUFFER

	if ret != 0 {
		return nil, nil, fmt.Errorf("initializeProcThreadAttributeList ret=%x err=%v attrListsize=%v", ret, err, attributeListSize)
	}

	fmt.Printf("Allocting Attribute List %d\n", attributeListSize)

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

// StringToUTF16Ptr converts a Go string into a pointer to a null-terminated UTF-16 wide string.
// This assumes str is of a UTF-8 compatible encoding so that it can be re-encoded as UTF-16.
func StringToUTF16Ptr(str string) *uint16 {
	wchars := utf16.Encode([]rune(str + "\x00"))
	return &wchars[0]
}

// StringToCharPtr converts a Go string into pointer to a null-terminated cstring.
// This assumes the go string is already ANSI encoded.
func StringToCharPtr(str string) *uint8 {
	chars := append([]byte(str), 0) // null terminated
	return &chars[0]
}

func echo() error {
	szCommand := ("ping localhost")

	pc, pipeIn, pipeOut, err := createPseudoConsoleAndPipes()

	if err != nil {
		return errors.Wrap(err, "failed to create pipes")
	}

	// Create & start thread to listen to the incoming pipe
	// Note: Using CRT-safe _beginthread() rather than CreateThread()
	//   HANDLE hPipeListenerThread{ reinterpret_cast<HANDLE>(_beginthread(PipeListener, 0, hPipeIn)) };

	go PipeListener(pipeIn)

	startupInfo, buffer, err := InitializeStartupInfoAttachedToPseudoConsole(pc)

	if err != nil {
		return errors.Wrap(err, "failed to InitializeStartupInfoAttachedToPseudoConsole")
	}

	var piClient syscall.ProcessInformation

	//prettyPrint(*startupInfo)

	err = win32Bool(syscall.Syscall12(CreateProcessA,
		10,
		0,
		uintptr(unsafe.Pointer(StringToCharPtr(szCommand))),
		0,
		0,
		0,
		uintptr(windows.EXTENDED_STARTUPINFO_PRESENT),
		0,
		0,
		uintptr(unsafe.Pointer(startupInfo)),
		uintptr(unsafe.Pointer(&piClient)),
		0,
		0))

	if err != nil {

		if errno, ok := err.(syscall.Errno); ok {
			return errors.Wrapf(err, "Create process failed with errno %X", uintptr(errno))
		}

		return errors.Wrap(err, "Create process failed")
	}

	// Wait up to 10s for ping process to complete
	r1, r2, err := syscall.Syscall(WaitForSingleObject, 2, uintptr(piClient.Thread), 10*1000, 0)
	fmt.Printf("WaitForSingleObject returned %X %X %v\n", r1, r2, err)
	if err != syscall.Errno(0) {
		return errors.Wrap(err, "WaitForSingleObjectd")
	}

	// Allow listening thread to catch-up with final output!
	//		Sleep(500);
	time.Sleep(500 * time.Millisecond)

	// --- CLOSEDOWN ---
	// Now safe to clean-up client app's process-info & thread

	_ = closeThisHandle(windows.Handle(piClient.Thread))
	_ = closeThisHandle(windows.Handle(piClient.Process))

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

	_ = closeThisHandle(pipeOut)
	_ = closeThisHandle(pipeIn)

	fmt.Printf("Buffer: %v\n", buffer)

	return nil

}

func PipeListener(pipe windows.Handle) {
	fmt.Printf("go started with arg: %s\n", pipe)

	console, err := getStdOut()

	if err != nil {
		panic(err) // TODO: error channel
	}

	fmt.Printf("Got a console %v\n", console)

	// const DWORD BUFF_SIZE{ 512 };
	const buffSize = 512

	szBuffer := make([]byte, buffSize)

	var dwBytesRead Dword
	var dwBytesWritten Dword

	for {
		// Read from the pipe

		// TODO: syscall.ReadFile
		fRead, _, err := syscall.Syscall6(ReadFile, 5, uintptr(pipe), uintptr(unsafe.Pointer(&szBuffer[0])), buffSize, uintptr(unsafe.Pointer(&dwBytesRead)), 0, 0)

		if err != syscall.Errno(0) {
			panic(err)
		}

		// TODO: syscall.WriteFile
		_, _, err = syscall.Syscall6(WriteFile, 5, uintptr(console), uintptr(unsafe.Pointer(&szBuffer[0])), uintptr(dwBytesRead), uintptr(unsafe.Pointer(&dwBytesWritten)), 0, 0)

		if err != syscall.Errno(0) {
			panic(err)
		}

		if fRead == 0 {
			break
		}

		if dwBytesRead < 1 {
			break
		}
	}
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
