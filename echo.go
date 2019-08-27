package main

import (
	"errors"
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	// TODO: handle the error and unload the library properly.
	kernel32, _                          = windows.LoadLibrary("kernel32.dll")
	ClosePseudoConsole, _                = windows.GetProcAddress(kernel32, "ClosePseudoConsole")
	CreatePipe, _                        = windows.GetProcAddress(kernel32, "CreatePipe")
	CreatePseudoConsole, _               = windows.GetProcAddress(kernel32, "CreatePseudoConsole")
	GetConsoleMode, _                    = windows.GetProcAddress(kernel32, "GetConsoleMode")
	GetConsoleScreenBufferInfo, _        = windows.GetProcAddress(kernel32, "GetConsoleScreenBufferInfo")
	GetStdHandle, _                      = windows.GetProcAddress(kernel32, "GetStdHandle")
	ResizePseudoConsole, _               = windows.GetProcAddress(kernel32, "ResizePseudoConsole")
	SetConsoleMode, _                    = windows.GetProcAddress(kernel32, "SetConsoleMode")
	CloseHandle, _                       = windows.GetProcAddress(kernel32, "CloseHandle")
	InitializeProcThreadAttributeList, _ = windows.GetProcAddress(kernel32, "InitializeProcThreadAttributeList")
	UpdateProcThreadAttribute, _         = windows.GetProcAddress(kernel32, "UpdateProcThreadAttribute")
)

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
		return err
	}

	var consoleMode Dword
	result, _, err := syscall.Syscall(GetConsoleMode, 2, console, uintptr(unsafe.Pointer(&consoleMode)), 0)

	if err != syscall.Errno(0) {
		return err
	}

	if result == 0 {
		return errors.New("GetConsoleMode failed")
	}

	result, _, err = syscall.Syscall(SetConsoleMode, 2, console, uintptr(consoleMode|windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING), 0)

	if err != syscall.Errno(0) {
		return err
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

func getScreenSize() (size *Coord, err error) {
	// Determine required size of Pseudo Console
	var consoleSize = new(Coord)
	var csbi ConsoleScreenBufferInfo

	console, err := getStdOut()

	if err != nil {
		return nil, err
	}

	syscall.Syscall(GetConsoleScreenBufferInfo, 2, console, uintptr(unsafe.Pointer(&csbi)), 0)

	consoleSize.X = uint16(csbi.srWindow.Right - csbi.srWindow.Left + 1)
	consoleSize.Y = uint16(csbi.srWindow.Bottom - csbi.srWindow.Top + 1)

	return consoleSize, nil
}

func createPipes() (read, write windows.Handle, err error) {
	read, write = windows.InvalidHandle, windows.InvalidHandle
	result, _, err := syscall.Syscall6(CreatePipe, 4, uintptr(unsafe.Pointer(&read)), uintptr(unsafe.Pointer(&write)), 0, 0, 0, 0)

	if err != syscall.Errno(0) {
		return
	}

	if result == 0 {
		err = errors.New("CreatePipe failed")
	}

	return
}

func closeThisHandle(h windows.Handle) error {
	if h != windows.InvalidHandle {
		ret, _, err := syscall.Syscall(CloseHandle, 1, uintptr(h), 0, 0)

		if err != syscall.Errno(0) {
			return err
		}

		if ret == 0 {
			return errors.New("CloseHandle failed")
		}
	}

	return nil
}

func createPseudoConsoleAndPipes() (pseudoConsole, pipeIn, pipeOut windows.Handle, err error) {

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

	var pc windows.Handle

	ret, _, err := syscall.Syscall6(
		CreatePseudoConsole,
		5,
		uintptr(unsafe.Pointer(&size)), // _In_ COORD size
		uintptr(pipePtyIn),             // _In_ HANDLE hInput
		uintptr(pipePtyOut),            // _In_ HANDLE hOutput
		0,
		uintptr(unsafe.Pointer(&pc)), // _Out_ HPCON* phPC
		0)

	if err != syscall.Errno(0) {
		return
	}

	if ret != 0 {
		err = fmt.Errorf("CreatePseudoConsole returned %X", ret)
	}

	_ = closeThisHandle(pipePtyIn)
	_ = closeThisHandle(pipePtyIn)

	return
}

// Initializes the specified startup info struct with the required properties and
// updates its thread attribute list with the specified ConPTY handle
func InitializeStartupInfoAttachedToPseudoConsole(pc windows.Handle) (*StartupInfoEx, error) {

	startupInfo := new(StartupInfoEx)
	startupInfo.StartupInfo.Cb = uint32(unsafe.Sizeof(*startupInfo))

	var attributeListSize int64

	ret, _, err := syscall.Syscall6(InitializeProcThreadAttributeList, 4,
		0, 1, 0, uintptr(unsafe.Pointer(&attributeListSize)), 0, 0)

	if err != syscall.Errno(0) {
		return nil, err
	}

	// windows.ERROR_INSUFFICIENT_BUFFER
	// TODO: check for windows.ERROR_INSUFFICIENT_BUFFER

	if ret != 0 {
		return nil, fmt.Errorf("initializeProcThreadAttributeList ret=%x err=%v attrListsize=%v\n", ret, err, attributeListSize)
	}

	var buffer = make([]byte, int(attributeListSize))
	startupInfo.AttributeList = &buffer[0]

	ret, _, err = syscall.Syscall6(InitializeProcThreadAttributeList, 4,
		uintptr(unsafe.Pointer(startupInfo.AttributeList)), 1, 0, uintptr(unsafe.Pointer(&attributeListSize)), 0, 0)
	if err != syscall.Errno(0) {
		return nil, err
	}

	// TODO: check for windows.ERROR_INSUFFICIENT_BUFFER
	if ret != 1 {
		return nil, fmt.Errorf("initializeProcThreadAttributeList ret=%x err=%v attrListsize=%v\n", ret, err, attributeListSize)
	}

	// TODO - error check here

	var ProcThreadAttributePseudoconsole uint32 = 0x00020016

	ret, _, err = syscall.Syscall9(
		UpdateProcThreadAttribute,
		7,
		uintptr(unsafe.Pointer(startupInfo.AttributeList)),
		uintptr(0),
		uintptr(ProcThreadAttributePseudoconsole),
		uintptr(pc),
		uintptr(unsafe.Sizeof(pc)),
		0,
		0,
		0,
		0)

	if err != syscall.Errno(0) {
		return nil, err
	}
	if ret != 1 {
		return nil, fmt.Errorf("updateProcThreadAttribute ret=%x err=%v\n", ret, err)
	}

	return startupInfo, nil
}

func echo() error {
	// TODO: copy to go format
	szCommand := "ping localhost" // wchar_t

	pc, pipeIn, pipeOut, err := createPseudoConsoleAndPipes()

	if err != nil {
		return err
	}

	// Create & start thread to listen to the incoming pipe
	// Note: Using CRT-safe _beginthread() rather than CreateThread()
	//   HANDLE hPipeListenerThread{ reinterpret_cast<HANDLE>(_beginthread(PipeListener, 0, hPipeIn)) };

	startupInfo, err := InitializeStartupInfoAttachedToPseudoConsole(pc)
}

/*
            {
                // Launch ping to emit some text back via the pipe
                PROCESS_INFORMATION piClient{};
                hr = CreateProcess(
                    NULL,                           // No module name - use Command Line
                    szCommand,                      // Command Line
                    NULL,                           // Process handle not inheritable
                    NULL,                           // Thread handle not inheritable
                    FALSE,                          // Inherit handles
                    EXTENDED_STARTUPINFO_PRESENT,   // Creation flags
                    NULL,                           // Use parent's environment block
                    NULL,                           // Use parent's starting directory
                    &startupInfo.StartupInfo,       // Pointer to STARTUPINFO
                    &piClient)                      // Pointer to PROCESS_INFORMATION
                    ? S_OK
                    : GetLastError();

                if (S_OK == hr)
                {
                    // Wait up to 10s for ping process to complete
                    WaitForSingleObject(piClient.hThread, 10 * 1000);

                    // Allow listening thread to catch-up with final output!
                    Sleep(500);
                }

                // --- CLOSEDOWN ---

                // Now safe to clean-up client app's process-info & thread
                CloseHandle(piClient.hThread);
                CloseHandle(piClient.hProcess);

                // Cleanup attribute list
                DeleteProcThreadAttributeList(startupInfo.lpAttributeList);
                free(startupInfo.lpAttributeList);
            }

            // Close ConPTY - this will terminate client process if running
            ClosePseudoConsole(hPC);

            // Clean-up the pipes
            if (INVALID_HANDLE_VALUE != hPipeOut) CloseHandle(hPipeOut);
            if (INVALID_HANDLE_VALUE != hPipeIn) CloseHandle(hPipeIn);
        }
    }

    return S_OK == hr ? EXIT_SUCCESS : EXIT_FAILURE;
}

/*


void __cdecl PipeListener(LPVOID pipe)
{
    HANDLE hPipe{ pipe };
    HANDLE hConsole{ GetStdHandle(STD_OUTPUT_HANDLE) };

    const DWORD BUFF_SIZE{ 512 };
    char szBuffer[BUFF_SIZE]{};

    DWORD dwBytesWritten{};
    DWORD dwBytesRead{};
    BOOL fRead{ FALSE };
    do
    {
        // Read from the pipe
        fRead = ReadFile(hPipe, szBuffer, BUFF_SIZE, &dwBytesRead, NULL);

        // Write received text to the Console
        // Note: Write to the Console using WriteFile(hConsole...), not printf()/puts() to
        // prevent partially-read VT sequences from corrupting output
        WriteFile(hConsole, szBuffer, dwBytesRead, &dwBytesWritten, NULL);

    } while (fRead && dwBytesRead >= 0);
}
*/
