package pty

import (
	"fmt"
	"io"
	"os"
	"time"
	"unsafe"

	"github.com/marcomorain/go-win-py/pkg/system"
	"github.com/pkg/errors"

	"golang.org/x/sys/windows"
)

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

// TODO: remove
func createPipes() (read, write windows.Handle, err error) {
	err = windows.CreatePipe(&read, &write, nil, 0)
	return
}

func createPseudoConsoleAndPipes() (pc windows.Handle, pipeIn, pipeOut *os.File, err error) {

	pipePtyIn, pipeOut, err := os.Pipe()
	if err != nil {
		return windows.InvalidHandle, nil, nil, errors.Wrap(err, "failed to create pipePtyIn pipe")
	}

	defer pipePtyIn.Close()

	pipeIn, pipePtyOut, err := os.Pipe()
	if err != nil {
		return windows.InvalidHandle, nil, nil, errors.Wrap(err, "failed to create pipePtyOut pipe")
	}

	defer pipePtyOut.Close()

	size, err := getScreenSize() // TODO: pass this is
	if err != nil {
		return 0, nil, nil, errors.Wrap(err, "failed to read screen size")
	}

	//fmt.Printf("Screen: %v %v\n", size.X, size.Y)

	console, err := system.CreatePseudoConsole(size, windows.Handle(pipePtyIn.Fd()), windows.Handle(pipePtyOut.Fd()))

	if err != nil {
		return windows.InvalidHandle, nil, nil, errors.Wrap(err, "CreatePseudoConsole failed")
	}
	return console, pipeIn, pipeOut, nil
}

// StartupInfoEx lint me
type StartupInfoEx struct {
	windows.StartupInfo
	AttributeList uintptr
}

// InitializeStartupInfoAttachedToPseudoConsole Initializes the specified startup info
// struct with the required properties and updates its thread attribute list with the
// specified ConPTY handle
func InitializeStartupInfoAttachedToPseudoConsole(pc windows.Handle) (*StartupInfoEx, error) {

	if pc == windows.InvalidHandle {
		return nil, errors.New("bad pc")
	}

	startupInfo := new(StartupInfoEx)

	startupInfo.StartupInfo.Cb = uint32(unsafe.Sizeof(*startupInfo))

	var attributeListSize int64

	err := system.InitializeProcThreadAttributeList(0, &attributeListSize)

	if err != windows.ERROR_INSUFFICIENT_BUFFER {
		return nil, errors.Wrap(err, "Failed to compute attribute list size")
	}

	heap, err := system.GetProcessHeap()

	if err != nil {
		return nil, errors.Wrap(err, "failed to get heap to alloc from")
	}

	const HeapZeroMemory = 0x00000008

	// TODO: Use an []byte rather than heap alloc here?
	startupInfo.AttributeList, err = system.HeapAlloc(heap, HeapZeroMemory, uintptr(attributeListSize))

	if err != nil {
		return nil, errors.Wrap(err, "failed to allocate memory")
	}

	err = system.InitializeProcThreadAttributeList(startupInfo.AttributeList, &attributeListSize)

	if err != nil {
		return nil, errors.Wrap(err, "Failed InitializeProcThreadAttributeList")
	}

	var ProcThreadAttributePseudoconsole uint32 = 0x00020016

	err = system.UpdateProcThreadAttribute(startupInfo.AttributeList, ProcThreadAttributePseudoconsole, uintptr(pc), unsafe.Sizeof(pc))

	return startupInfo, errors.Wrap(err, "Failed UpdateProcThreadAttribute")
}

// RunProcessWithPty runs the process in a PTY
func RunProcessWithPty(command string, stdin io.Reader, stdout io.Writer) error {

	pc, pipeIn, pipeOut, err := createPseudoConsoleAndPipes()

	if err != nil {
		return errors.Wrap(err, "failed to create pipes")
	}

	//fmt.Printf("pc is 0x%08X\n", pc)

	// Clean-up the pipes
	defer pipeOut.Close()
	defer pipeIn.Close()

	//console, err := windows.GetStdHandle(windows.STD_OUTPUT_HANDLE)

	if err != nil {
		return err
	}

	//stdin, err := windows.GetStdHandle(windows.STD_INPUT_HANDLE)

	startupInfo, err := InitializeStartupInfoAttachedToPseudoConsole(pc)

	if err != nil {
		return errors.Wrap(err, "failed to InitializeStartupInfoAttachedToPseudoConsole")
	}

	procInfo := new(windows.ProcessInformation)

	var flags uint32 = windows.EXTENDED_STARTUPINFO_PRESENT

	commandLine := windows.StringToUTF16Ptr(command)

	inheritHandles := false

	err = windows.CreateProcess(nil, commandLine, nil, nil, inheritHandles,
		flags,
		nil, nil, &startupInfo.StartupInfo, procInfo)

	if err != nil {
		return errors.Wrap(err, "Create process failed")
	}

	defer system.ClosePseudoConsole(pc)
	defer windows.CloseHandle(procInfo.Process)
	defer windows.CloseHandle(procInfo.Thread)

	//fmt.Printf("Process: %v %v Thread: %v %v\n", procInfo.ProcessId, procInfo.Process, procInfo.ThreadId, procInfo.Thread)

	// Create & start thread to listen to the incoming pipe
	go io.Copy(stdout, pipeIn)
	go io.Copy(pipeOut, stdin)

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

	err = system.DeleteProcThreadAttributeList(startupInfo.AttributeList)

	// free(startupInfo.lpAttributeList); This is GCed by golang

	return err

}
