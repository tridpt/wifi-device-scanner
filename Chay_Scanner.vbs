Option Explicit

Dim fso, shell, currentDir, pythonExe, scriptPath

Set fso = CreateObject("Scripting.FileSystemObject")
Set shell = CreateObject("WScript.Shell")

currentDir = fso.GetParentFolderName(WScript.ScriptFullName)
shell.CurrentDirectory = currentDir

' Uu tien su dung Python trong .venv cua repository clone
pythonExe = fso.BuildPath(currentDir, ".venv\Scripts\pythonw.exe")
If Not fso.FileExists(pythonExe) Then
    ' Tuong thich voi workspace cu co .venv o thu muc cha
    pythonExe = fso.BuildPath(currentDir, "..\.venv\Scripts\pythonw.exe")
End If
scriptPath = fso.BuildPath(currentDir, "main.py")

If fso.FileExists(pythonExe) Then
    shell.Run """" & pythonExe & """ """ & scriptPath & """", 0, False
Else
    ' Neu khong co thi chay pythonw he thong
    shell.Run "pythonw.exe """ & scriptPath & """", 0, False
End If
