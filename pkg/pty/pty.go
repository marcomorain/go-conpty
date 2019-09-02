package pty

import (
	"encoding/json"
	"fmt"
	"time"
	"unsafe"

	"github.com/marcomorain/go-win-py/pkg/system"
	"github.com/pkg/errors"

	"github.com/davecgh/go-spew/spew"
	"golang.org/x/sys/windows"
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

	pc, err = system.CreatePseudoConsole(size, pipePtyIn, pipePtyOut)

	if err != nil {
		return 0, 0, 0, errors.Wrap(err, "CreatePseudoConsole failed")
	}
	return pc, pipeIn, pipeOut, nil
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
	startupInfo.AttributeList, err = system.HeapAlloc(heap, HeapZeroMemory, uintptr(attributeListSize))

	if err != nil {
		return nil, errors.Wrap(err, "failed to allocate memory")
	}

	spew.Dump(startupInfo)

	err = system.InitializeProcThreadAttributeList(startupInfo.AttributeList, &attributeListSize)

	if err != nil {
		return nil, errors.Wrap(err, "Failed InitializeProcThreadAttributeList")
	}

	var ProcThreadAttributePseudoconsole uint32 = 0x00020016

	//PrettyPrint(startupInfo)

	err = system.UpdateProcThreadAttribute(startupInfo.AttributeList, ProcThreadAttributePseudoconsole, uintptr(pc), unsafe.Sizeof(pc))

	return startupInfo, errors.Wrap(err, "Failed UpdateProcThreadAttribute")
}

// Echo test entry point
func RunProcessWithPty(command string) error {

	pc, pipeIn, pipeOut, err := createPseudoConsoleAndPipes()

	if err != nil {
		return errors.Wrap(err, "failed to create pipes")
	}

	fmt.Printf("pc is %x\n", pc)

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

	err = windows.CreateProcess(nil, commandLine, nil, nil, inheritHandles,
		flags,
		nil, nil, &(startupInfo.StartupInfo), &procInfo)

	if err != nil {
		return errors.Wrap(err, "Create process failed")
	}

	defer system.ClosePseudoConsole(pc)
	defer windows.CloseHandle(procInfo.Process)
	defer windows.CloseHandle(procInfo.Thread)

	fmt.Printf("Process: %v %v Thread: %v %v\n", procInfo.ProcessId, procInfo.Process, procInfo.ThreadId, procInfo.Thread)

	// Create & start thread to listen to the incoming pipe
	go system.Copy(console, pipeIn)
	go system.Copy(pipeOut, stdin)

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

	spew.Dump(startupInfo)

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
