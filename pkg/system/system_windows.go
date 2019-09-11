package system

import (
	"fmt"
	"io"
	"syscall"
	"unsafe"

	"github.com/pkg/errors"
	"golang.org/x/sys/windows"
)

// TODO: handle the error and unload the library properly.
var (
	kernel32, _                          = windows.LoadLibrary("kernel32.dll")
	closePseudoConsole, _                = windows.GetProcAddress(kernel32, "ClosePseudoConsole")
	createPseudoConsole, _               = windows.GetProcAddress(kernel32, "CreatePseudoConsole")
	getProcessHeap, _                    = windows.GetProcAddress(kernel32, "GetProcessHeap")
	heapAlloc, _                         = windows.GetProcAddress(kernel32, "HeapAlloc")
	deleteProcThreadAttributeList, _     = windows.GetProcAddress(kernel32, "DeleteProcThreadAttributeList")
	initializeProcThreadAttributeList, _ = windows.GetProcAddress(kernel32, "InitializeProcThreadAttributeList")
	resizePseudoConsole, _               = windows.GetProcAddress(kernel32, "ResizePseudoConsole")
	updateProcThreadAttribute, _         = windows.GetProcAddress(kernel32, "UpdateProcThreadAttribute")
)

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

func win32Handle(r1, r2 uintptr, err error) (uintptr, error) {
	//fmt.Printf("win32Handle: r1=%x r2=%x err=%v\n", r1, r2, err)
	if err != windows.Errno(0) {
		return 0, err
	}
	return r1, nil
}

// InitializeProcThreadAttributeList Initializes the specified list of attributes for process and thread creation.
// https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-initializeprocthreadattributelist
func InitializeProcThreadAttributeList(attributeList uintptr, size *int64) error {
	return win32Bool(syscall.Syscall6(initializeProcThreadAttributeList,
		4,
		attributeList,
		1,
		0,
		uintptr(unsafe.Pointer(size)),
		0,
		0))
}

// UpdateProcThreadAttribute Updates the specified attribute in a list of attributes for process and thread creation.
// https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute
func UpdateProcThreadAttribute(attributeList uintptr, flags uint32, value, size uintptr) error {
	fmt.Printf("UpdateProcThreadAttribute value=%08x size=%d\n", value, size)
	return win32Bool(syscall.Syscall9(
		updateProcThreadAttribute,
		7,
		attributeList,
		0,
		uintptr(flags),
		value,
		size,
		0,
		0,
		0,
		0))
}

// CreatePseudoConsole Creates a new pseudoconsole object for the calling process.
// https://docs.microsoft.com/en-us/windows/console/createpseudoconsole
func CreatePseudoConsole(size *windows.Coord, input, output windows.Handle) (windows.Handle, error) {

	phPC := new(windows.Handle)
	*phPC = windows.InvalidHandle

	err := win32Hresult(syscall.Syscall6(
		createPseudoConsole,
		5,
		uintptr(unsafe.Pointer(size)), // _In_ COORD size
		uintptr(input),                // _In_ HANDLE hInput
		uintptr(output),               // _In_ HANDLE hOutput
		0,
		uintptr(unsafe.Pointer(phPC)), // _Out_ HPCON* phPC
		0))

	return *phPC, errors.Wrap(err, "CreatePseudoConsole failed")
}

// ResizePseudoConsole Resizes the internal buffers for a pseudoconsole to the given size.
// https://docs.microsoft.com/en-us/windows/console/resizepseudoconsole
func ResizePseudoConsole(pc windows.Handle, size *windows.Coord) error {
	return win32Hresult(syscall.Syscall(
		resizePseudoConsole,
		2,
		uintptr(pc),                   // _In_ HPCON hPC
		uintptr(unsafe.Pointer(size)), // _In_ COORD size
		0))
}

// ProcThreadAttributeEntry This structure stores the value for each attribute
type ProcThreadAttributeEntry struct {
	Attribute *int32 // PROC_THREAD_ATTRIBUTE_xxx
	cbSize    int64
	lpValue   uintptr
}

// ProcThreadAttributeList This structure contains a list of attributes that have been added using UpdateProcThreadAttribute
type ProcThreadAttributeList struct {
	Flags    int32
	Size     int32
	Count    int32
	Reserved int32
	Unknown  uintptr
	//Entries  *ProcThreadAttributeEntry
	Entries uintptr
}

// DeleteProcThreadAttributeList Deletes the specified list of attributes for process and thread creation.
// https://docs.microsoft.com/en-gb/windows/win32/api/processthreadsapi/nf-processthreadsapi-deleteprocthreadattributelist
func DeleteProcThreadAttributeList(attributeList uintptr) error {
	err := win32Void(syscall.Syscall(deleteProcThreadAttributeList, 1, attributeList, 0, 0))
	return errors.Wrap(err, "DeleteProcThreadAttributeList")
}

// ClosePseudoConsole Closes a pseudoconsole from the given handle.
// https://docs.microsoft.com/en-us/windows/console/closepseudoconsole
func ClosePseudoConsole(pc windows.Handle) error {
	// Close ConPTY - this will terminate client process if running
	//fmt.Printf("Closing console %v\n", pc)
	err := win32Void(syscall.Syscall(closePseudoConsole, 1, uintptr(pc), 0, 0)) // _In_ HPCON hPC
	return errors.Wrap(err, "Failed to close PseudoConsole")
}

// Copy data from src int dst.
// Returns the number of bytes written, and an error if one occured.
func Copy(dst windows.Handle, src io.Reader) (int64, error) {
	buffer := make([]byte, 1024)
	var written int64 = 0

	for {
		// Read from the pipe
		//var bytesRead uint32

		bytesRead, err := src.Read(buffer)
		//err = windows.ReadFile(src, buffer, &bytesRead, nil)

		if err != nil || bytesRead == 0 {
			return written, err
		}

		var bytesWritten uint32
		err = windows.WriteFile(dst, buffer[:bytesRead], &bytesWritten, nil)

		if err != nil {
			return written, err
		}

		written += int64(bytesWritten)

	}
}

func Copy2(dst io.Writer, src windows.Handle) (int, error) {
	buffer := make([]byte, 1024)
	var written = 0

	for {
		// Read from the pipe
		var bytesRead uint32
		err := windows.ReadFile(src, buffer, &bytesRead, nil)

		if err != nil || bytesRead == 0 {
			return written, err
		}

		bytesWritten, err := dst.Write(buffer[:bytesRead])

		//var bytesWritten uint32
		//err = windows.WriteFile(dst, buffer[:bytesRead], &bytesWritten, nil)

		if err != nil {
			return written, err
		}

		written += bytesWritten

	}
}

// GetProcessHeap Retrieves a handle to the default heap of the calling process.
// This handle can then be used in subsequent calls to the heap functions.
// https://docs.microsoft.com/en-gb/windows/win32/api/heapapi/nf-heapapi-getprocessheap
func GetProcessHeap() (windows.Handle, error) {
	heap, err := win32Handle(syscall.Syscall(getProcessHeap, 0, 0, 0, 0))
	return windows.Handle(heap), err
}

// HeapAlloc Allocates a block of memory from a heap. The allocated memory is not movable.
// https://docs.microsoft.com/en-us/windows/win32/api/heapapi/nf-heapapi-heapalloc
func HeapAlloc(heap windows.Handle, flags uint32, bytes uintptr) (uintptr, error) {
	return win32Handle(syscall.Syscall(heapAlloc, 3, uintptr(heap), uintptr(flags), bytes))
}
