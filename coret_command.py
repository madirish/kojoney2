
import coret_std_unix

def executeCommand(cmdLine):

    command = cmdLine[0]

    if command == "wget":
        return coret_std_unix.wget(cmdLine)
    elif command == "curl":
        return coret_std_unix.curl(cmdLine)
    else:
        return False
