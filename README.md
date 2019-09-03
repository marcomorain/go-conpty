# Go ConPTY

This library exposes the (Windows ConPTY API)[https://blogs.msdn.microsoft.com/commandline/2018/08/02/windows-command-line-introducing-the-windows-pseudo-console-conpty/] to `golang`. It was written by [CircleCI](https://circleci.com).

# Status

This library is not complete - there are two show-stopper bugs in it:

1. On one test machine, the sample project successfully executes with a PTY less than 50% of the time. The failure is due to the process created with `CreateProcessW` launching, and immediately failing with [exit code `0xc0000142`](https://blogs.msdn.microsoft.com/winsdk/2015/06/03/what-is-up-with-the-application-failed-to-initialize-properly-0xc0000142-error/).
2. On another test machine, calls to `CreatePseudoConsole` returns `ERROR_INSUFFICIENT_BUFFER` on ever call.

To help debug these issues, there are many calls to `printf` and `spew`.

# Architecture

This project is split into two library packages, and some sample commands:

- `pkg/pty`: A golang package that exposes the ConPTY API.
- `pkg/system`: A low level wrapper over the ConPTY Win32 API.
- `cmd/echocon.go`: A port of [the EchoCon.cpp sample](https://github.com/microsoft/terminal/blob/e6767acf467083780335958a7954addacad1115a/samples/ConPTY/EchoCon/EchoCon/EchoCon.cpp) to go, using this library.
