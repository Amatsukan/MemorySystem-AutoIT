Func _winapi_getlasterror($curerr = @error, $curext = @extended)
	Local $aresult = DllCall("kernel32.dll", "dword", "GetLastError")
	Return SetError($curerr, $curext, $aresult[0])
EndFunc

Func _winapi_setlasterror($ierrcode, $curerr = @error, $curext = @extended)
	DllCall("kernel32.dll", "none", "SetLastError", "dword", $ierrcode)
	Return SetError($curerr, $curext)
EndFunc

Func _security__adjusttokenprivileges($htoken, $fdisableall, $pnewstate, $ibufferlen, $pprevstate = 0, $prequired = 0)
	Local $aresult = DllCall("advapi32.dll", "bool", "AdjustTokenPrivileges", "handle", $htoken, "bool", $fdisableall, "ptr", $pnewstate, "dword", $ibufferlen, "ptr", $pprevstate, "ptr", $prequired)
	If @error Then Return SetError(@error, @extended, False)
	Return $aresult[0]
EndFunc

Func _security__getaccountsid($saccount, $ssystem = "")
	Local $aacct = _security__lookupaccountname($saccount, $ssystem)
	If @error Then Return SetError(@error, 0, 0)
	Return _security__stringsidtosid($aacct[0])
EndFunc

Func _security__getlengthsid($psid)
	If NOT _security__isvalidsid($psid) Then Return SetError(-1, 0, 0)
	Local $aresult = DllCall("advapi32.dll", "dword", "GetLengthSid", "ptr", $psid)
	If @error Then Return SetError(@error, @extended, 0)
	Return $aresult[0]
EndFunc

Func _security__gettokeninformation($htoken, $iclass)
	Local $aresult = DllCall("advapi32.dll", "bool", "GetTokenInformation", "handle", $htoken, "int", $iclass, "ptr", 0, "dword", 0, "dword*", 0)
	If @error Then Return SetError(@error, @extended, 0)
	If NOT $aresult[0] Then Return 0
	Local $tbuffer = DllStructCreate("byte[" & $aresult[5] & "]")
	Local $pbuffer = DllStructGetPtr($tbuffer)
	$aresult = DllCall("advapi32.dll", "bool", "GetTokenInformation", "handle", $htoken, "int", $iclass, "ptr", $pbuffer, "dword", $aresult[5], "dword*", 0)
	If @error Then Return SetError(@error, @extended, 0)
	If NOT $aresult[0] Then Return 0
	Return $tbuffer
EndFunc

Func _security__impersonateself($ilevel = 2)
	Local $aresult = DllCall("advapi32.dll", "bool", "ImpersonateSelf", "int", $ilevel)
	If @error Then Return SetError(@error, @extended, False)
	Return $aresult[0]
EndFunc

Func _security__isvalidsid($psid)
	Local $aresult = DllCall("advapi32.dll", "bool", "IsValidSid", "ptr", $psid)
	If @error Then Return SetError(@error, @extended, False)
	Return $aresult[0]
EndFunc

Func _security__lookupaccountname($saccount, $ssystem = "")
	Local $tdata = DllStructCreate("byte SID[256]")
	Local $psid = DllStructGetPtr($tdata, "SID")
	Local $aresult = DllCall("advapi32.dll", "bool", "LookupAccountNameW", "wstr", $ssystem, "wstr", $saccount, "ptr", $psid, "dword*", 256, "wstr", "", "dword*", 256, "int*", 0)
	If @error Then Return SetError(@error, @extended, 0)
	If NOT $aresult[0] Then Return 0
	Local $aacct[3]
	$aacct[0] = _security__sidtostringsid($psid)
	$aacct[1] = $aresult[5]
	$aacct[2] = $aresult[7]
	Return $aacct
EndFunc

Func _security__lookupaccountsid($vsid)
	Local $psid, $aacct[3]
	If IsString($vsid) Then
		Local $tsid = _security__stringsidtosid($vsid)
		$psid = DllStructGetPtr($tsid)
	Else
		$psid = $vsid
	EndIf
	If NOT _security__isvalidsid($psid) Then Return SetError(-1, 0, 0)
	Local $aresult = DllCall("advapi32.dll", "bool", "LookupAccountSidW", "ptr", 0, "ptr", $psid, "wstr", "", "dword*", 256, "wstr", "", "dword*", 256, "int*", 0)
	If @error Then Return SetError(@error, @extended, 0)
	If NOT $aresult[0] Then Return 0
	Local $aacct[3]
	$aacct[0] = $aresult[3]
	$aacct[1] = $aresult[5]
	$aacct[2] = $aresult[7]
	Return $aacct
EndFunc

Func _security__lookupprivilegevalue($ssystem, $sname)
	Local $aresult = DllCall("advapi32.dll", "int", "LookupPrivilegeValueW", "wstr", $ssystem, "wstr", $sname, "int64*", 0)
	If @error Then Return SetError(@error, @extended, 0)
	Return SetError(0, $aresult[0], $aresult[3])
EndFunc

Func _security__openprocesstoken($hprocess, $iaccess)
	Local $aresult = DllCall("advapi32.dll", "int", "OpenProcessToken", "handle", $hprocess, "dword", $iaccess, "ptr", 0)
	If @error Then Return SetError(@error, @extended, 0)
	Return SetError(0, $aresult[0], $aresult[3])
EndFunc

Func _security__openthreadtoken($iaccess, $hthread = 0, $fopenasself = False)
	If $hthread = 0 Then $hthread = DllCall("kernel32.dll", "handle", "GetCurrentThread")
	If @error Then Return SetError(@error, @extended, 0)
	Local $aresult = DllCall("advapi32.dll", "bool", "OpenThreadToken", "handle", $hthread[0], "dword", $iaccess, "int", $fopenasself, "ptr*", 0)
	If @error Then Return SetError(@error, @extended, 0)
	Return SetError(0, $aresult[0], $aresult[4])
EndFunc

Func _security__openthreadtokenex($iaccess, $hthread = 0, $fopenasself = False)
	Local $htoken = _security__openthreadtoken($iaccess, $hthread, $fopenasself)
	If $htoken = 0 Then
		If _winapi_getlasterror() <> $error_no_token Then Return SetError(-3, _winapi_getlasterror(), 0)
		If NOT _security__impersonateself() Then Return SetError(-1, _winapi_getlasterror(), 0)
		$htoken = _security__openthreadtoken($iaccess, $hthread, $fopenasself)
		If $htoken = 0 Then Return SetError(-2, _winapi_getlasterror(), 0)
	EndIf
	Return $htoken
EndFunc

Func _security__setprivilege($htoken, $sprivilege, $fenable)
	Local $iluid = _security__lookupprivilegevalue("", $sprivilege)
	If $iluid = 0 Then Return SetError(-1, 0, False)
	Local $tcurrstate = DllStructCreate($tagtoken_privileges)
	Local $pcurrstate = DllStructGetPtr($tcurrstate)
	Local $icurrstate = DllStructGetSize($tcurrstate)
	Local $tprevstate = DllStructCreate($tagtoken_privileges)
	Local $pprevstate = DllStructGetPtr($tprevstate)
	Local $iprevstate = DllStructGetSize($tprevstate)
	Local $trequired = DllStructCreate("int Data")
	Local $prequired = DllStructGetPtr($trequired)
	DllStructSetData($tcurrstate, "Count", 1)
	DllStructSetData($tcurrstate, "LUID", $iluid)
	If NOT _security__adjusttokenprivileges($htoken, False, $pcurrstate, $icurrstate, $pprevstate, $prequired) Then Return SetError(-2, @error, False)
	DllStructSetData($tprevstate, "Count", 1)
	DllStructSetData($tprevstate, "LUID", $iluid)
	Local $iattributes = DllStructGetData($tprevstate, "Attributes")
	If $fenable Then
		$iattributes = BitOR($iattributes, $se_privilege_enabled)
	Else
		$iattributes = BitAND($iattributes, BitNOT($se_privilege_enabled))
	EndIf
	DllStructSetData($tprevstate, "Attributes", $iattributes)
	If NOT _security__adjusttokenprivileges($htoken, False, $pprevstate, $iprevstate, $pcurrstate, $prequired) Then Return SetError(-3, @error, False)
	Return True
EndFunc

Func _security__sidtostringsid($psid)
	If NOT _security__isvalidsid($psid) Then Return SetError(-1, 0, "")
	Local $aresult = DllCall("advapi32.dll", "int", "ConvertSidToStringSidW", "ptr", $psid, "ptr*", 0)
	If @error Then Return SetError(@error, @extended, "")
	If NOT $aresult[0] Then Return ""
	Local $tbuffer = DllStructCreate("wchar Text[256]", $aresult[2])
	Local $ssid = DllStructGetData($tbuffer, "Text")
	DllCall("Kernel32.dll", "ptr", "LocalFree", "ptr", $aresult[2])
	Return $ssid
EndFunc

Func _security__sidtypestr($itype)
	Switch $itype
		Case 1
			Return "User"
		Case 2
			Return "Group"
		Case 3
			Return "Domain"
		Case 4
			Return "Alias"
		Case 5
			Return "Well Known Group"
		Case 6
			Return "Deleted Account"
		Case 7
			Return "Invalid"
		Case 8
			Return "Invalid"
		Case 9
			Return "Computer"
		Case Else
			Return "Unknown SID Type"
	EndSwitch
EndFunc

Func _security__stringsidtosid($ssid)
	Local $aresult = DllCall("advapi32.dll", "bool", "ConvertStringSidToSidW", "wstr", $ssid, "ptr*", 0)
	If @error Then Return SetError(@error, @extended, 0)
	If NOT $aresult[0] Then Return 0
	Local $isize = _security__getlengthsid($aresult[2])
	Local $tbuffer = DllStructCreate("byte Data[" & $isize & "]", $aresult[2])
	Local $tsid = DllStructCreate("byte Data[" & $isize & "]")
	DllStructSetData($tsid, "Data", DllStructGetData($tbuffer, "Data"))
	DllCall("kernel32.dll", "ptr", "LocalFree", "ptr", $aresult[2])
	Return $tsid
EndFunc

Global Const $tagmemmap = "handle hProc;ulong_ptr Size;ptr Mem"

Func _memfree(ByRef $tmemmap)
	Local $pmemory = DllStructGetData($tmemmap, "Mem")
	Local $hprocess = DllStructGetData($tmemmap, "hProc")
	Local $bresult = _memvirtualfreeex($hprocess, $pmemory, 0, $mem_release)
	DllCall("kernel32.dll", "bool", "CloseHandle", "handle", $hprocess)
	If @error Then Return SetError(@error, @extended, False)
	Return $bresult
EndFunc

Func _memglobalalloc($ibytes, $iflags = 0)
	Local $aresult = DllCall("kernel32.dll", "handle", "GlobalAlloc", "uint", $iflags, "ulong_ptr", $ibytes)
	If @error Then Return SetError(@error, @extended, 0)
	Return $aresult[0]
EndFunc

Func _memglobalfree($hmem)
	Local $aresult = DllCall("kernel32.dll", "ptr", "GlobalFree", "handle", $hmem)
	If @error Then Return SetError(@error, @extended, False)
	Return $aresult[0]
EndFunc

Func _memgloballock($hmem)
	Local $aresult = DllCall("kernel32.dll", "ptr", "GlobalLock", "handle", $hmem)
	If @error Then Return SetError(@error, @extended, 0)
	Return $aresult[0]
EndFunc

Func _memglobalsize($hmem)
	Local $aresult = DllCall("kernel32.dll", "ulong_ptr", "GlobalSize", "handle", $hmem)
	If @error Then Return SetError(@error, @extended, 0)
	Return $aresult[0]
EndFunc

Func _memglobalunlock($hmem)
	Local $aresult = DllCall("kernel32.dll", "bool", "GlobalUnlock", "handle", $hmem)
	If @error Then Return SetError(@error, @extended, 0)
	Return $aresult[0]
EndFunc

Func _meminit($hwnd, $isize, ByRef $tmemmap)
	Local $aresult = DllCall("User32.dll", "dword", "GetWindowThreadProcessId", "hwnd", $hwnd, "dword*", 0)
	If @error Then Return SetError(@error, @extended, 0)
	Local $iprocessid = $aresult[2]
	If $iprocessid = 0 Then Return SetError(1, 0, 0)
	Local $iaccess = BitOR($process_vm_operation, $process_vm_read, $process_vm_write)
	Local $hprocess = __mem_openprocess($iaccess, False, $iprocessid, True)
	Local $ialloc = BitOR($mem_reserve, $mem_commit)
	Local $pmemory = _memvirtualallocex($hprocess, 0, $isize, $ialloc, $page_readwrite)
	If $pmemory = 0 Then Return SetError(2, 0, 0)
	$tmemmap = DllStructCreate($tagmemmap)
	DllStructSetData($tmemmap, "hProc", $hprocess)
	DllStructSetData($tmemmap, "Size", $isize)
	DllStructSetData($tmemmap, "Mem", $pmemory)
	Return $pmemory
EndFunc

Func _memmovememory($psource, $pdest, $ilength)
	DllCall("kernel32.dll", "none", "RtlMoveMemory", "ptr", $pdest, "ptr", $psource, "ulong_ptr", $ilength)
	If @error Then Return SetError(@error, @extended)
EndFunc

Func _memread(ByRef $tmemmap, $psrce, $pdest, $isize)
	Local $aresult = DllCall("kernel32.dll", "bool", "ReadProcessMemory", "handle", DllStructGetData($tmemmap, "hProc"), "ptr", $psrce, "ptr", $pdest, "ulong_ptr", $isize, "ulong_ptr*", 0)
	If @error Then Return SetError(@error, @extended, False)
	Return $aresult[0]
EndFunc

Func _memwrite(ByRef $tmemmap, $psrce, $pdest = 0, $isize = 0, $ssrce = "ptr")
	If $pdest = 0 Then $pdest = DllStructGetData($tmemmap, "Mem")
	If $isize = 0 Then $isize = DllStructGetData($tmemmap, "Size")
	Local $aresult = DllCall("kernel32.dll", "bool", "WriteProcessMemory", "handle", DllStructGetData($tmemmap, "hProc"), "ptr", $pdest, $ssrce, $psrce, "ulong_ptr", $isize, "ulong_ptr*", 0)
	If @error Then Return SetError(@error, @extended, False)
	Return $aresult[0]
EndFunc

Func _memvirtualalloc($paddress, $isize, $iallocation, $iprotect)
	Local $aresult = DllCall("kernel32.dll", "ptr", "VirtualAlloc", "ptr", $paddress, "ulong_ptr", $isize, "dword", $iallocation, "dword", $iprotect)
	If @error Then Return SetError(@error, @extended, 0)
	Return $aresult[0]
EndFunc

Func _memvirtualallocex($hprocess, $paddress, $isize, $iallocation, $iprotect)
	Local $aresult = DllCall("kernel32.dll", "ptr", "VirtualAllocEx", "handle", $hprocess, "ptr", $paddress, "ulong_ptr", $isize, "dword", $iallocation, "dword", $iprotect)
	If @error Then Return SetError(@error, @extended, 0)
	Return $aresult[0]
EndFunc

Func _memvirtualfree($paddress, $isize, $ifreetype)
	Local $aresult = DllCall("kernel32.dll", "bool", "VirtualFree", "ptr", $paddress, "ulong_ptr", $isize, "dword", $ifreetype)
	If @error Then Return SetError(@error, @extended, False)
	Return $aresult[0]
EndFunc

Func _memvirtualfreeex($hprocess, $paddress, $isize, $ifreetype)
	Local $aresult = DllCall("kernel32.dll", "bool", "VirtualFreeEx", "handle", $hprocess, "ptr", $paddress, "ulong_ptr", $isize, "dword", $ifreetype)
	If @error Then Return SetError(@error, @extended, False)
	Return $aresult[0]
EndFunc

Func __mem_openprocess($iaccess, $finherit, $iprocessid, $fdebugpriv = False)
	Local $aresult = DllCall("kernel32.dll", "handle", "OpenProcess", "dword", $iaccess, "bool", $finherit, "dword", $iprocessid)
	If @error Then Return SetError(@error, @extended, 0)
	If $aresult[0] Then Return $aresult[0]
	If NOT $fdebugpriv Then Return 0
	Local $htoken = _security__openthreadtokenex(BitOR($token_adjust_privileges, $token_query))
	If @error Then Return SetError(@error, @extended, 0)
	_security__setprivilege($htoken, "SeDebugPrivilege", True)
	Local $ierror = @error
	Local $ilasterror = @extended
	Local $iret = 0
	If NOT @error Then
		$aresult = DllCall("kernel32.dll", "handle", "OpenProcess", "dword", $iaccess, "bool", $finherit, "dword", $iprocessid)
		$ierror = @error
		$ilasterror = @extended
		If $aresult[0] Then $iret = $aresult[0]
		_security__setprivilege($htoken, "SeDebugPrivilege", False)
		If @error Then
			$ierror = @error
			$ilasterror = @extended
		EndIf
	EndIf
	DllCall("kernel32.dll", "bool", "CloseHandle", "handle", $htoken)
	Return SetError($ierror, $ilasterror, $iret)
EndFunc

;pt2 ************************************

Func _sendmessage($hwnd, $imsg, $wparam = 0, $lparam = 0, $ireturn = 0, $wparamtype = "wparam", $lparamtype = "lparam", $sreturntype = "lresult")
	Local $aresult = DllCall("user32.dll", $sreturntype, "SendMessageW", "hwnd", $hwnd, "uint", $imsg, $wparamtype, $wparam, $lparamtype, $lparam)
	If @error Then Return SetError(@error, @extended, "")
	If $ireturn >= 0 AND $ireturn <= 4 Then Return $aresult[$ireturn]
	Return $aresult
EndFunc

Func _sendmessagea($hwnd, $imsg, $wparam = 0, $lparam = 0, $ireturn = 0, $wparamtype = "wparam", $lparamtype = "lparam", $sreturntype = "lresult")
	Local $aresult = DllCall("user32.dll", $sreturntype, "SendMessageA", "hwnd", $hwnd, "uint", $imsg, $wparamtype, $wparam, $lparamtype, $lparam)
	If @error Then Return SetError(@error, @extended, "")
	If $ireturn >= 0 AND $ireturn <= 4 Then Return $aresult[$ireturn]
	Return $aresult
EndFunc

;pt 3 ****************************

Func _winapi_attachconsole($iprocessid = -1)
	Local $aresult = DllCall("kernel32.dll", "bool", "AttachConsole", "dword", $iprocessid)
	If @error Then Return SetError(@error, @extended, False)
	Return $aresult[0]
EndFunc

Func _winapi_attachthreadinput($iattach, $iattachto, $fattach)
	Local $aresult = DllCall("user32.dll", "bool", "AttachThreadInput", "dword", $iattach, "dword", $iattachto, "bool", $fattach)
	If @error Then Return SetError(@error, @extended, False)
	Return $aresult[0]
EndFunc

Func _winapi_beep($ifreq = 500, $iduration = 1000)
	Local $aresult = DllCall("kernel32.dll", "bool", "Beep", "dword", $ifreq, "dword", $iduration)
	If @error Then Return SetError(@error, @extended, False)
	Return $aresult[0]
EndFunc

Func _winapi_bitblt($hdestdc, $ixdest, $iydest, $iwidth, $iheight, $hsrcdc, $ixsrc, $iysrc, $irop)
	Local $aresult = DllCall("gdi32.dll", "bool", "BitBlt", "handle", $hdestdc, "int", $ixdest, "int", $iydest, "int", $iwidth, "int", $iheight, "handle", $hsrcdc, "int", $ixsrc, "int", $iysrc, "dword", $irop)
	If @error Then Return SetError(@error, @extended, False)
	Return $aresult[0]
EndFunc

Func _winapi_callnexthookex($hhk, $icode, $wparam, $lparam)
	Local $aresult = DllCall("user32.dll", "lresult", "CallNextHookEx", "handle", $hhk, "int", $icode, "wparam", $wparam, "lparam", $lparam)
	If @error Then Return SetError(@error, @extended, -1)
	Return $aresult[0]
EndFunc

Func _winapi_callwindowproc($lpprevwndfunc, $hwnd, $msg, $wparam, $lparam)
	Local $aresult = DllCall("user32.dll", "lresult", "CallWindowProc", "ptr", $lpprevwndfunc, "hwnd", $hwnd, "uint", $msg, "wparam", $wparam, "lparam", $lparam)
	If @error Then Return SetError(@error, @extended, -1)
	Return $aresult[0]
EndFunc

Func _winapi_clienttoscreen($hwnd, ByRef $tpoint)
	Local $ppoint = DllStructGetPtr($tpoint)
	DllCall("user32.dll", "bool", "ClientToScreen", "hwnd", $hwnd, "ptr", $ppoint)
	Return SetError(@error, @extended, $tpoint)
EndFunc

Func _winapi_closehandle($hobject)
	Local $aresult = DllCall("kernel32.dll", "bool", "CloseHandle", "handle", $hobject)
	If @error Then Return SetError(@error, @extended, False)
	Return $aresult[0]
EndFunc

Func _winapi_combinergn($hrgndest, $hrgnsrc1, $hrgnsrc2, $icombinemode)
	Local $aresult = DllCall("gdi32.dll", "int", "CombineRgn", "handle", $hrgndest, "handle", $hrgnsrc1, "handle", $hrgnsrc2, "int", $icombinemode)
	If @error Then Return SetError(@error, @extended, 0)
	Return $aresult[0]
EndFunc

Func _winapi_commdlgextendederror()
	Local Const $cderr_dialogfailure = 65535
	Local Const $cderr_findresfailure = 6
	Local Const $cderr_initialization = 2
	Local Const $cderr_loadresfailure = 7
	Local Const $cderr_loadstrfailure = 5
	Local Const $cderr_lockresfailure = 8
	Local Const $cderr_memallocfailure = 9
	Local Const $cderr_memlockfailure = 10
	Local Const $cderr_nohinstance = 4
	Local Const $cderr_nohook = 11
	Local Const $cderr_notemplate = 3
	Local Const $cderr_registermsgfail = 12
	Local Const $cderr_structsize = 1
	Local Const $fnerr_buffertoosmall = 12291
	Local Const $fnerr_invalidfilename = 12290
	Local Const $fnerr_subclassfailure = 12289
	Local $aresult = DllCall("comdlg32.dll", "dword", "CommDlgExtendedError")
	If @error Then Return SetError(@error, @extended, 0)
	Switch $aresult[0]
		Case $cderr_dialogfailure
			Return SetError($aresult[0], 0, "The dialog box could not be created." & @LF & "The common dialog box function's call to the DialogBox function failed." & @LF & "For example, this error occurs if the common dialog box call specifies an invalid window handle.")
		Case $cderr_findresfailure
			Return SetError($aresult[0], 0, "The common dialog box function failed to find a specified resource.")
		Case $cderr_initialization
			Return SetError($aresult[0], 0, "The common dialog box function failed during initialization." & @LF & "This error often occurs when sufficient memory is not available.")
		Case $cderr_loadresfailure
			Return SetError($aresult[0], 0, "The common dialog box function failed to load a specified resource.")
		Case $cderr_loadstrfailure
			Return SetError($aresult[0], 0, "The common dialog box function failed to load a specified string.")
		Case $cderr_lockresfailure
			Return SetError($aresult[0], 0, "The common dialog box function failed to lock a specified resource.")
		Case $cderr_memallocfailure
			Return SetError($aresult[0], 0, "The common dialog box function was unable to allocate memory for internal structures.")
		Case $cderr_memlockfailure
			Return SetError($aresult[0], 0, "The common dialog box function was unable to lock the memory associated with a handle.")
		Case $cderr_nohinstance
			Return SetError($aresult[0], 0, "The ENABLETEMPLATE flag was set in the Flags member of the initialization structure for the corresponding common dialog box," & @LF & "but you failed to provide a corresponding instance handle.")
		Case $cderr_nohook
			Return SetError($aresult[0], 0, "The ENABLEHOOK flag was set in the Flags member of the initialization structure for the corresponding common dialog box," & @LF & "but you failed to provide a pointer to a corresponding hook procedure.")
		Case $cderr_notemplate
			Return SetError($aresult[0], 0, "The ENABLETEMPLATE flag was set in the Flags member of the initialization structure for the corresponding common dialog box," & @LF & "but you failed to provide a corresponding template.")
		Case $cderr_registermsgfail
			Return SetError($aresult[0], 0, "The RegisterWindowMessage function returned an error code when it was called by the common dialog box function.")
		Case $cderr_structsize
			Return SetError($aresult[0], 0, "The lStructSize member of the initialization structure for the corresponding common dialog box is invalid")
		Case $fnerr_buffertoosmall
			Return SetError($aresult[0], 0, "The buffer pointed to by the lpstrFile member of the OPENFILENAME structure is too small for the file name specified by the user." & @LF & "The first two bytes of the lpstrFile buffer contain an integer value specifying the size, in TCHARs, required to receive the full name.")
		Case $fnerr_invalidfilename
			Return SetError($aresult[0], 0, "A file name is invalid.")
		Case $fnerr_subclassfailure
			Return SetError($aresult[0], 0, "An attempt to subclass a list box failed because sufficient memory was not available.")
	EndSwitch
	Return Hex($aresult[0])
EndFunc

Func _winapi_copyicon($hicon)
	Local $aresult = DllCall("user32.dll", "handle", "CopyIcon", "handle", $hicon)
	If @error Then Return SetError(@error, @extended, 0)
	Return $aresult[0]
EndFunc

Func _winapi_createbitmap($iwidth, $iheight, $iplanes = 1, $ibitsperpel = 1, $pbits = 0)
	Local $aresult = DllCall("gdi32.dll", "handle", "CreateBitmap", "int", $iwidth, "int", $iheight, "uint", $iplanes, "uint", $ibitsperpel, "ptr", $pbits)
	If @error Then Return SetError(@error, @extended, 0)
	Return $aresult[0]
EndFunc

Func _winapi_createcompatiblebitmap($hdc, $iwidth, $iheight)
	Local $aresult = DllCall("gdi32.dll", "handle", "CreateCompatibleBitmap", "handle", $hdc, "int", $iwidth, "int", $iheight)
	If @error Then Return SetError(@error, @extended, 0)
	Return $aresult[0]
EndFunc

Func _winapi_createcompatibledc($hdc)
	Local $aresult = DllCall("gdi32.dll", "handle", "CreateCompatibleDC", "handle", $hdc)
	If @error Then Return SetError(@error, @extended, 0)
	Return $aresult[0]
EndFunc

Func _winapi_createevent($pattributes = 0, $fmanualreset = True, $finitialstate = True, $sname = "")
	Local $snametype = "wstr"
	If $sname = "" Then
		$sname = 0
		$snametype = "ptr"
	EndIf
	Local $aresult = DllCall("kernel32.dll", "handle", "CreateEventW", "ptr", $pattributes, "bool", $fmanualreset, "bool", $finitialstate, $snametype, $sname)
	If @error Then Return SetError(@error, @extended, 0)
	Return $aresult[0]
EndFunc

Func _winapi_createfile($sfilename, $icreation, $iaccess = 4, $ishare = 0, $iattributes = 0, $psecurity = 0)
	Local $ida = 0, $ism = 0, $icd = 0, $ifa = 0
	If BitAND($iaccess, 1) <> 0 Then $ida = BitOR($ida, $generic_execute)
	If BitAND($iaccess, 2) <> 0 Then $ida = BitOR($ida, $generic_read)
	If BitAND($iaccess, 4) <> 0 Then $ida = BitOR($ida, $generic_write)
	If BitAND($ishare, 1) <> 0 Then $ism = BitOR($ism, $file_share_delete)
	If BitAND($ishare, 2) <> 0 Then $ism = BitOR($ism, $file_share_read)
	If BitAND($ishare, 4) <> 0 Then $ism = BitOR($ism, $file_share_write)
	Switch $icreation
		Case 0
			$icd = $create_new
		Case 1
			$icd = $create_always
		Case 2
			$icd = $open_existing
		Case 3
			$icd = $open_always
		Case 4
			$icd = $truncate_existing
	EndSwitch
	If BitAND($iattributes, 1) <> 0 Then $ifa = BitOR($ifa, $file_attribute_archive)
	If BitAND($iattributes, 2) <> 0 Then $ifa = BitOR($ifa, $file_attribute_hidden)
	If BitAND($iattributes, 4) <> 0 Then $ifa = BitOR($ifa, $file_attribute_readonly)
	If BitAND($iattributes, 8) <> 0 Then $ifa = BitOR($ifa, $file_attribute_system)
	Local $aresult = DllCall("kernel32.dll", "handle", "CreateFileW", "wstr", $sfilename, "dword", $ida, "dword", $ism, "ptr", $psecurity, "dword", $icd, "dword", $ifa, "ptr", 0)
	If @error OR $aresult[0] = Ptr(-1) Then Return SetError(@error, @extended, 0)
	Return $aresult[0]
EndFunc

Func _winapi_createfont($nheight, $nwidth, $nescape = 0, $norientn = 0, $fnweight = $__winapiconstant_fw_normal, $bitalic = False, $bunderline = False, $bstrikeout = False, $ncharset = $__winapiconstant_default_charset, $noutputprec = $__winapiconstant_out_default_precis, $nclipprec = $__winapiconstant_clip_default_precis, $nquality = $__winapiconstant_default_quality, $npitch = 0, $szface = "Arial")
	Local $aresult = DllCall("gdi32.dll", "handle", "CreateFontW", "int", $nheight, "int", $nwidth, "int", $nescape, "int", $norientn, "int", $fnweight, "dword", $bitalic, "dword", $bunderline, "dword", $bstrikeout, "dword", $ncharset, "dword", $noutputprec, "dword", $nclipprec, "dword", $nquality, "dword", $npitch, "wstr", $szface)
	If @error Then Return SetError(@error, @extended, 0)
	Return $aresult[0]
EndFunc

Func _winapi_createfontindirect($tlogfont)
	Local $aresult = DllCall("gdi32.dll", "handle", "CreateFontIndirectW", "ptr", DllStructGetPtr($tlogfont))
	If @error Then Return SetError(@error, @extended, 0)
	Return $aresult[0]
EndFunc

Func _winapi_createpen($ipenstyle, $iwidth, $ncolor)
	Local $aresult = DllCall("gdi32.dll", "handle", "CreatePen", "int", $ipenstyle, "int", $iwidth, "dword", $ncolor)
	If @error Then Return SetError(@error, @extended, 0)
	Return $aresult[0]
EndFunc

Func _winapi_createprocess($sappname, $scommand, $psecurity, $pthread, $finherit, $iflags, $penviron, $sdir, $pstartupinfo, $pprocess)
	Local $pcommand = 0
	Local $sappnametype = "wstr", $sdirtype = "wstr"
	If $sappname = "" Then
		$sappnametype = "ptr"
		$sappname = 0
	EndIf
	If $scommand <> "" Then
		Local $tcommand = DllStructCreate("wchar Text[" & 260 + 1 & "]")
		$pcommand = DllStructGetPtr($tcommand)
		DllStructSetData($tcommand, "Text", $scommand)
	EndIf
	If $sdir = "" Then
		$sdirtype = "ptr"
		$sdir = 0
	EndIf
	Local $aresult = DllCall("kernel32.dll", "bool", "CreateProcessW", $sappnametype, $sappname, "ptr", $pcommand, "ptr", $psecurity, "ptr", $pthread, "bool", $finherit, "dword", $iflags, "ptr", $penviron, $sdirtype, $sdir, "ptr", $pstartupinfo, "ptr", $pprocess)
	If @error Then Return SetError(@error, @extended, False)
	Return $aresult[0]
EndFunc

Func _winapi_createrectrgn($ileftrect, $itoprect, $irightrect, $ibottomrect)
	Local $aresult = DllCall("gdi32.dll", "handle", "CreateRectRgn", "int", $ileftrect, "int", $itoprect, "int", $irightrect, "int", $ibottomrect)
	If @error Then Return SetError(@error, @extended, 0)
	Return $aresult[0]
EndFunc

Func _winapi_createroundrectrgn($ileftrect, $itoprect, $irightrect, $ibottomrect, $iwidthellipse, $iheightellipse)
	Local $aresult = DllCall("gdi32.dll", "handle", "CreateRoundRectRgn", "int", $ileftrect, "int", $itoprect, "int", $irightrect, "int", $ibottomrect, "int", $iwidthellipse, "int", $iheightellipse)
	If @error Then Return SetError(@error, @extended, 0)
	Return $aresult[0]
EndFunc

Func _winapi_createsolidbitmap($hwnd, $icolor, $iwidth, $iheight, $brgb = 1)
	Local $hdc = _winapi_getdc($hwnd)
	Local $hdestdc = _winapi_createcompatibledc($hdc)
	Local $hbitmap = _winapi_createcompatiblebitmap($hdc, $iwidth, $iheight)
	Local $hold = _winapi_selectobject($hdestdc, $hbitmap)
	Local $trect = DllStructCreate($tagrect)
	DllStructSetData($trect, 1, 0)
	DllStructSetData($trect, 2, 0)
	DllStructSetData($trect, 3, $iwidth)
	DllStructSetData($trect, 4, $iheight)
	If $brgb Then
		$icolor = BitOR(BitAND($icolor, 65280), BitShift(BitAND($icolor, 255), -16), BitShift(BitAND($icolor, 16711680), 16))
	EndIf
	Local $hbrush = _winapi_createsolidbrush($icolor)
	_winapi_fillrect($hdestdc, DllStructGetPtr($trect), $hbrush)
	If @error Then
		_winapi_deleteobject($hbitmap)
		$hbitmap = 0
	EndIf
	_winapi_deleteobject($hbrush)
	_winapi_releasedc($hwnd, $hdc)
	_winapi_selectobject($hdestdc, $hold)
	_winapi_deletedc($hdestdc)
	If NOT $hbitmap Then Return SetError(1, 0, 0)
	Return $hbitmap
EndFunc

Func _winapi_createsolidbrush($ncolor)
	Local $aresult = DllCall("gdi32.dll", "handle", "CreateSolidBrush", "dword", $ncolor)
	If @error Then Return SetError(@error, @extended, 0)
	Return $aresult[0]
EndFunc

Func _winapi_createwindowex($iexstyle, $sclass, $sname, $istyle, $ix, $iy, $iwidth, $iheight, $hparent, $hmenu = 0, $hinstance = 0, $pparam = 0)
	If $hinstance = 0 Then $hinstance = _winapi_getmodulehandle("")
	Local $aresult = DllCall("user32.dll", "hwnd", "CreateWindowExW", "dword", $iexstyle, "wstr", $sclass, "wstr", $sname, "dword", $istyle, "int", $ix, "int", $iy, "int", $iwidth, "int", $iheight, "hwnd", $hparent, "handle", $hmenu, "handle", $hinstance, "ptr", $pparam)
	If @error Then Return SetError(@error, @extended, 0)
	Return $aresult[0]
EndFunc

Func _winapi_defwindowproc($hwnd, $imsg, $iwparam, $ilparam)
	Local $aresult = DllCall("user32.dll", "lresult", "DefWindowProc", "hwnd", $hwnd, "uint", $imsg, "wparam", $iwparam, "lparam", $ilparam)
	If @error Then Return SetError(@error, @extended, 0)
	Return $aresult[0]
EndFunc

Func _winapi_deletedc($hdc)
	Local $aresult = DllCall("gdi32.dll", "bool", "DeleteDC", "handle", $hdc)
	If @error Then Return SetError(@error, @extended, False)
	Return $aresult[0]
EndFunc

Func _winapi_deleteobject($hobject)
	Local $aresult = DllCall("gdi32.dll", "bool", "DeleteObject", "handle", $hobject)
	If @error Then Return SetError(@error, @extended, False)
	Return $aresult[0]
EndFunc

Func _winapi_destroyicon($hicon)
	Local $aresult = DllCall("user32.dll", "bool", "DestroyIcon", "handle", $hicon)
	If @error Then Return SetError(@error, @extended, False)
	Return $aresult[0]
EndFunc

Func _winapi_destroywindow($hwnd)
	Local $aresult = DllCall("user32.dll", "bool", "DestroyWindow", "hwnd", $hwnd)
	If @error Then Return SetError(@error, @extended, False)
	Return $aresult[0]
EndFunc

Func _winapi_drawedge($hdc, $ptrrect, $nedgetype, $grfflags)
	Local $aresult = DllCall("user32.dll", "bool", "DrawEdge", "handle", $hdc, "ptr", $ptrrect, "uint", $nedgetype, "uint", $grfflags)
	If @error Then Return SetError(@error, @extended, False)
	Return $aresult[0]
EndFunc

Func _winapi_drawframecontrol($hdc, $ptrrect, $ntype, $nstate)
	Local $aresult = DllCall("user32.dll", "bool", "DrawFrameControl", "handle", $hdc, "ptr", $ptrrect, "uint", $ntype, "uint", $nstate)
	If @error Then Return SetError(@error, @extended, False)
	Return $aresult[0]
EndFunc

Func _winapi_drawicon($hdc, $ix, $iy, $hicon)
	Local $aresult = DllCall("user32.dll", "bool", "DrawIcon", "handle", $hdc, "int", $ix, "int", $iy, "handle", $hicon)
	If @error Then Return SetError(@error, @extended, False)
	Return $aresult[0]
EndFunc

Func _winapi_drawiconex($hdc, $ix, $iy, $hicon, $iwidth = 0, $iheight = 0, $istep = 0, $hbrush = 0, $iflags = 3)
	Local $ioptions
	Switch $iflags
		Case 1
			$ioptions = $__winapiconstant_di_mask
		Case 2
			$ioptions = $__winapiconstant_di_image
		Case 3
			$ioptions = $__winapiconstant_di_normal
		Case 4
			$ioptions = $__winapiconstant_di_compat
		Case 5
			$ioptions = $__winapiconstant_di_defaultsize
		Case Else
			$ioptions = $__winapiconstant_di_nomirror
	EndSwitch
	Local $aresult = DllCall("user32.dll", "bool", "DrawIconEx", "handle", $hdc, "int", $ix, "int", $iy, "handle", $hicon, "int", $iwidth, "int", $iheight, "uint", $istep, "handle", $hbrush, "uint", $ioptions)
	If @error Then Return SetError(@error, @extended, False)
	Return $aresult[0]
EndFunc

Func _winapi_drawline($hdc, $ix1, $iy1, $ix2, $iy2)
	_winapi_moveto($hdc, $ix1, $iy1)
	If @error Then Return SetError(@error, @extended, False)
	_winapi_lineto($hdc, $ix2, $iy2)
	If @error Then Return SetError(@error, @extended, False)
	Return True
EndFunc

Func _winapi_drawtext($hdc, $stext, ByRef $trect, $iflags)
	Local $aresult = DllCall("user32.dll", "int", "DrawTextW", "handle", $hdc, "wstr", $stext, "int", -1, "ptr", DllStructGetPtr($trect), "uint", $iflags)
	If @error Then Return SetError(@error, @extended, 0)
	Return $aresult[0]
EndFunc

Func _winapi_enablewindow($hwnd, $fenable = True)
	Local $aresult = DllCall("user32.dll", "bool", "EnableWindow", "hwnd", $hwnd, "bool", $fenable)
	If @error Then Return SetError(@error, @extended, False)
	Return $aresult[0]
EndFunc

Func _winapi_enumdisplaydevices($sdevice, $idevnum)
	Local $pname = 0, $iflags = 0, $adevice[5]
	If $sdevice <> "" Then
		Local $tname = DllStructCreate("wchar Text[" & StringLen($sdevice) + 1 & "]")
		$pname = DllStructGetPtr($tname)
		DllStructSetData($tname, "Text", $sdevice)
	EndIf
	Local $tdevice = DllStructCreate($tagdisplay_device)
	Local $pdevice = DllStructGetPtr($tdevice)
	Local $idevice = DllStructGetSize($tdevice)
	DllStructSetData($tdevice, "Size", $idevice)
	DllCall("user32.dll", "bool", "EnumDisplayDevicesW", "ptr", $pname, "dword", $idevnum, "ptr", $pdevice, "dword", 1)
	If @error Then Return SetError(@error, @extended, 0)
	Local $in = DllStructGetData($tdevice, "Flags")
	If BitAND($in, $__winapiconstant_display_device_attached_to_desktop) <> 0 Then $iflags = BitOR($iflags, 1)
	If BitAND($in, $__winapiconstant_display_device_primary_device) <> 0 Then $iflags = BitOR($iflags, 2)
	If BitAND($in, $__winapiconstant_display_device_mirroring_driver) <> 0 Then $iflags = BitOR($iflags, 4)
	If BitAND($in, $__winapiconstant_display_device_vga_compatible) <> 0 Then $iflags = BitOR($iflags, 8)
	If BitAND($in, $__winapiconstant_display_device_removable) <> 0 Then $iflags = BitOR($iflags, 16)
	If BitAND($in, $__winapiconstant_display_device_modespruned) <> 0 Then $iflags = BitOR($iflags, 32)
	$adevice[0] = True
	$adevice[1] = DllStructGetData($tdevice, "Name")
	$adevice[2] = DllStructGetData($tdevice, "String")
	$adevice[3] = $iflags
	$adevice[4] = DllStructGetData($tdevice, "ID")
	Return $adevice
EndFunc

Func _winapi_enumwindows($fvisible = True, $hwnd = Default)
	__winapi_enumwindowsinit()
	If $hwnd = Default Then $hwnd = _winapi_getdesktopwindow()
	__winapi_enumwindowschild($hwnd, $fvisible)
	Return $__gawinlist_winapi
EndFunc

Func __winapi_enumwindowsadd($hwnd, $sclass = "")
	If $sclass = "" Then $sclass = _winapi_getclassname($hwnd)
	$__gawinlist_winapi[0][0] += 1
	Local $icount = $__gawinlist_winapi[0][0]
	If $icount >= $__gawinlist_winapi[0][1] Then
		ReDim $__gawinlist_winapi[$icount + 64][2]
		$__gawinlist_winapi[0][1] += 64
	EndIf
	$__gawinlist_winapi[$icount][0] = $hwnd
	$__gawinlist_winapi[$icount][1] = $sclass
EndFunc

Func __winapi_enumwindowschild($hwnd, $fvisible = True)
	$hwnd = _winapi_getwindow($hwnd, $__winapiconstant_gw_child)
	While $hwnd <> 0
		If (NOT $fvisible) OR _winapi_iswindowvisible($hwnd) Then
			__winapi_enumwindowschild($hwnd, $fvisible)
			__winapi_enumwindowsadd($hwnd)
		EndIf
		$hwnd = _winapi_getwindow($hwnd, $__winapiconstant_gw_hwndnext)
	WEnd
EndFunc

Func __winapi_enumwindowsinit()
	ReDim $__gawinlist_winapi[64][2]
	$__gawinlist_winapi[0][0] = 0
	$__gawinlist_winapi[0][1] = 64
EndFunc

Func _winapi_enumwindowspopup()
	__winapi_enumwindowsinit()
	Local $hwnd = _winapi_getwindow(_winapi_getdesktopwindow(), $__winapiconstant_gw_child)
	Local $sclass
	While $hwnd <> 0
		If _winapi_iswindowvisible($hwnd) Then
			$sclass = _winapi_getclassname($hwnd)
			If $sclass = "#32768" Then
				__winapi_enumwindowsadd($hwnd)
			ElseIf $sclass = "ToolbarWindow32" Then
				__winapi_enumwindowsadd($hwnd)
			ElseIf $sclass = "ToolTips_Class32" Then
				__winapi_enumwindowsadd($hwnd)
			ElseIf $sclass = "BaseBar" Then
				__winapi_enumwindowschild($hwnd)
			EndIf
		EndIf
		$hwnd = _winapi_getwindow($hwnd, $__winapiconstant_gw_hwndnext)
	WEnd
	Return $__gawinlist_winapi
EndFunc

Func _winapi_enumwindowstop()
	__winapi_enumwindowsinit()
	Local $hwnd = _winapi_getwindow(_winapi_getdesktopwindow(), $__winapiconstant_gw_child)
	While $hwnd <> 0
		If _winapi_iswindowvisible($hwnd) Then __winapi_enumwindowsadd($hwnd)
		$hwnd = _winapi_getwindow($hwnd, $__winapiconstant_gw_hwndnext)
	WEnd
	Return $__gawinlist_winapi
EndFunc

Func _winapi_expandenvironmentstrings($sstring)
	Local $aresult = DllCall("kernel32.dll", "dword", "ExpandEnvironmentStringsW", "wstr", $sstring, "wstr", "", "dword", 4096)
	If @error Then Return SetError(@error, @extended, "")
	Return $aresult[2]
EndFunc

Func _winapi_extracticonex($sfile, $iindex, $plarge, $psmall, $iicons)
	Local $aresult = DllCall("shell32.dll", "uint", "ExtractIconExW", "wstr", $sfile, "int", $iindex, "handle", $plarge, "handle", $psmall, "uint", $iicons)
	If @error Then Return SetError(@error, @extended, 0)
	Return $aresult[0]
EndFunc

Func _winapi_fatalappexit($smessage)
	DllCall("kernel32.dll", "none", "FatalAppExitW", "uint", 0, "wstr", $smessage)
	If @error Then Return SetError(@error, @extended)
EndFunc

Func _winapi_fillrect($hdc, $ptrrect, $hbrush)
	Local $aresult
	If IsPtr($hbrush) Then
		$aresult = DllCall("user32.dll", "int", "FillRect", "handle", $hdc, "ptr", $ptrrect, "handle", $hbrush)
	Else
		$aresult = DllCall("user32.dll", "int", "FillRect", "handle", $hdc, "ptr", $ptrrect, "dword", $hbrush)
	EndIf
	If @error Then Return SetError(@error, @extended, False)
	Return $aresult[0]
EndFunc

Func _winapi_findexecutable($sfilename, $sdirectory = "")
	Local $aresult = DllCall("shell32.dll", "INT", "FindExecutableW", "wstr", $sfilename, "wstr", $sdirectory, "wstr", "")
	If @error Then Return SetError(@error, @extended, 0)
	Return SetExtended($aresult[0], $aresult[3])
EndFunc

Func _winapi_findwindow($sclassname, $swindowname)
	Local $aresult = DllCall("user32.dll", "hwnd", "FindWindowW", "wstr", $sclassname, "wstr", $swindowname)
	If @error Then Return SetError(@error, @extended, 0)
	Return $aresult[0]
EndFunc

Func _winapi_flashwindow($hwnd, $finvert = True)
	Local $aresult = DllCall("user32.dll", "bool", "FlashWindow", "hwnd", $hwnd, "bool", $finvert)
	If @error Then Return SetError(@error, @extended, False)
	Return $aresult[0]
EndFunc

Func _winapi_flashwindowex($hwnd, $iflags = 3, $icount = 3, $itimeout = 0)
	Local $tflash = DllStructCreate($tagflashwinfo)
	Local $pflash = DllStructGetPtr($tflash)
	Local $iflash = DllStructGetSize($tflash)
	Local $imode = 0
	If BitAND($iflags, 1) <> 0 Then $imode = BitOR($imode, $__winapiconstant_flashw_caption)
	If BitAND($iflags, 2) <> 0 Then $imode = BitOR($imode, $__winapiconstant_flashw_tray)
	If BitAND($iflags, 4) <> 0 Then $imode = BitOR($imode, $__winapiconstant_flashw_timer)
	If BitAND($iflags, 8) <> 0 Then $imode = BitOR($imode, $__winapiconstant_flashw_timernofg)
	DllStructSetData($tflash, "Size", $iflash)
	DllStructSetData($tflash, "hWnd", $hwnd)
	DllStructSetData($tflash, "Flags", $imode)
	DllStructSetData($tflash, "Count", $icount)
	DllStructSetData($tflash, "Timeout", $itimeout)
	Local $aresult = DllCall("user32.dll", "bool", "FlashWindowEx", "ptr", $pflash)
	If @error Then Return SetError(@error, @extended, False)
	Return $aresult[0]
EndFunc

Func _winapi_floattoint($nfloat)
	Local $tfloat = DllStructCreate("float")
	Local $tint = DllStructCreate("int", DllStructGetPtr($tfloat))
	DllStructSetData($tfloat, 1, $nfloat)
	Return DllStructGetData($tint, 1)
EndFunc

Func _winapi_flushfilebuffers($hfile)
	Local $aresult = DllCall("kernel32.dll", "bool", "FlushFileBuffers", "handle", $hfile)
	If @error Then Return SetError(@error, @extended, False)
	Return $aresult[0]
EndFunc

Func _winapi_formatmessage($iflags, $psource, $imessageid, $ilanguageid, ByRef $pbuffer, $isize, $varguments)
	Local $sbuffertype = "ptr"
	If IsString($pbuffer) Then $sbuffertype = "wstr"
	Local $aresult = DllCall("Kernel32.dll", "dword", "FormatMessageW", "dword", $iflags, "ptr", $psource, "dword", $imessageid, "dword", $ilanguageid, $sbuffertype, $pbuffer, "dword", $isize, "ptr", $varguments)
	If @error Then Return SetError(@error, @extended, 0)
	If $sbuffertype = "wstr" Then $pbuffer = $aresult[5]
	Return $aresult[0]
EndFunc

Func _winapi_framerect($hdc, $ptrrect, $hbrush)
	Local $aresult = DllCall("user32.dll", "int", "FrameRect", "handle", $hdc, "ptr", $ptrrect, "handle", $hbrush)
	If @error Then Return SetError(@error, @extended, False)
	Return $aresult[0]
EndFunc

Func _winapi_freelibrary($hmodule)
	Local $aresult = DllCall("kernel32.dll", "bool", "FreeLibrary", "handle", $hmodule)
	If @error Then Return SetError(@error, @extended, False)
	Return $aresult[0]
EndFunc

Func _winapi_getancestor($hwnd, $iflags = 1)
	Local $aresult = DllCall("user32.dll", "hwnd", "GetAncestor", "hwnd", $hwnd, "uint", $iflags)
	If @error Then Return SetError(@error, @extended, 0)
	Return $aresult[0]
EndFunc

Func _winapi_getasynckeystate($ikey)
	Local $aresult = DllCall("user32.dll", "short", "GetAsyncKeyState", "int", $ikey)
	If @error Then Return SetError(@error, @extended, 0)
	Return $aresult[0]
EndFunc

Func _winapi_getbkmode($hdc)
	Local $aresult = DllCall("gdi32.dll", "int", "GetBkMode", "handle", $hdc)
	If @error Then Return SetError(@error, @extended, 0)
	Return $aresult[0]
EndFunc

Func _winapi_getclassname($hwnd)
	If NOT IsHWnd($hwnd) Then $hwnd = GUICtrlGetHandle($hwnd)
	Local $aresult = DllCall("user32.dll", "int", "GetClassNameW", "hwnd", $hwnd, "wstr", "", "int", 4096)
	If @error Then Return SetError(@error, @extended, False)
	Return SetExtended($aresult[0], $aresult[2])
EndFunc

Func _winapi_getclientheight($hwnd)
	Local $trect = _winapi_getclientrect($hwnd)
	If @error Then Return SetError(@error, @extended, 0)
	Return DllStructGetData($trect, "Bottom") - DllStructGetData($trect, "Top")
EndFunc

Func _winapi_getclientwidth($hwnd)
	Local $trect = _winapi_getclientrect($hwnd)
	If @error Then Return SetError(@error, @extended, 0)
	Return DllStructGetData($trect, "Right") - DllStructGetData($trect, "Left")
EndFunc

Func _winapi_getclientrect($hwnd)
	Local $trect = DllStructCreate($tagrect)
	DllCall("user32.dll", "bool", "GetClientRect", "hwnd", $hwnd, "ptr", DllStructGetPtr($trect))
	If @error Then Return SetError(@error, @extended, 0)
	Return $trect
EndFunc

Func _winapi_getcurrentprocess()
	Local $aresult = DllCall("kernel32.dll", "handle", "GetCurrentProcess")
	If @error Then Return SetError(@error, @extended, 0)
	Return $aresult[0]
EndFunc

Func _winapi_getcurrentprocessid()
	Local $aresult = DllCall("kernel32.dll", "dword", "GetCurrentProcessId")
	If @error Then Return SetError(@error, @extended, 0)
	Return $aresult[0]
EndFunc

Func _winapi_getcurrentthread()
	Local $aresult = DllCall("kernel32.dll", "handle", "GetCurrentThread")
	If @error Then Return SetError(@error, @extended, 0)
	Return $aresult[0]
EndFunc

Func _winapi_getcurrentthreadid()
	Local $aresult = DllCall("kernel32.dll", "dword", "GetCurrentThreadId")
	If @error Then Return SetError(@error, @extended, 0)
	Return $aresult[0]
EndFunc

Func _winapi_getcursorinfo()
	Local $tcursor = DllStructCreate($tagcursorinfo)
	Local $icursor = DllStructGetSize($tcursor)
	DllStructSetData($tcursor, "Size", $icursor)
	DllCall("user32.dll", "bool", "GetCursorInfo", "ptr", DllStructGetPtr($tcursor))
	If @error Then Return SetError(@error, @extended, 0)
	Local $acursor[5]
	$acursor[0] = True
	$acursor[1] = DllStructGetData($tcursor, "Flags") <> 0
	$acursor[2] = DllStructGetData($tcursor, "hCursor")
	$acursor[3] = DllStructGetData($tcursor, "X")
	$acursor[4] = DllStructGetData($tcursor, "Y")
	Return $acursor
EndFunc

Func _winapi_getdc($hwnd)
	Local $aresult = DllCall("user32.dll", "handle", "GetDC", "hwnd", $hwnd)
	If @error Then Return SetError(@error, @extended, 0)
	Return $aresult[0]
EndFunc

Func _winapi_getdesktopwindow()
	Local $aresult = DllCall("user32.dll", "hwnd", "GetDesktopWindow")
	If @error Then Return SetError(@error, @extended, 0)
	Return $aresult[0]
EndFunc

Func _winapi_getdevicecaps($hdc, $iindex)
	Local $aresult = DllCall("gdi32.dll", "int", "GetDeviceCaps", "handle", $hdc, "int", $iindex)
	If @error Then Return SetError(@error, @extended, 0)
	Return $aresult[0]
EndFunc

Func _winapi_getdibits($hdc, $hbmp, $istartscan, $iscanlines, $pbits, $pbi, $iusage)
	Local $aresult = DllCall("gdi32.dll", "int", "GetDIBits", "handle", $hdc, "handle", $hbmp, "uint", $istartscan, "uint", $iscanlines, "ptr", $pbits, "ptr", $pbi, "uint", $iusage)
	If @error Then Return SetError(@error, @extended, False)
	Return $aresult[0]
EndFunc

Func _winapi_getdlgctrlid($hwnd)
	Local $aresult = DllCall("user32.dll", "int", "GetDlgCtrlID", "hwnd", $hwnd)
	If @error Then Return SetError(@error, @extended, 0)
	Return $aresult[0]
EndFunc

Func _winapi_getdlgitem($hwnd, $iitemid)
	Local $aresult = DllCall("user32.dll", "hwnd", "GetDlgItem", "hwnd", $hwnd, "int", $iitemid)
	If @error Then Return SetError(@error, @extended, 0)
	Return $aresult[0]
EndFunc

Func _winapi_getfocus()
	Local $aresult = DllCall("user32.dll", "hwnd", "GetFocus")
	If @error Then Return SetError(@error, @extended, 0)
	Return $aresult[0]
EndFunc

Func _winapi_getforegroundwindow()
	Local $aresult = DllCall("user32.dll", "hwnd", "GetForegroundWindow")
	If @error Then Return SetError(@error, @extended, 0)
	Return $aresult[0]
EndFunc

Func _winapi_getguiresources($iflag = 0, $hprocess = -1)
	If $hprocess = -1 Then $hprocess = _winapi_getcurrentprocess()
	Local $aresult = DllCall("user32.dll", "dword", "GetGuiResources", "handle", $hprocess, "dword", $iflag)
	If @error Then Return SetError(@error, @extended, 0)
	Return $aresult[0]
EndFunc

Func _winapi_geticoninfo($hicon)
	Local $tinfo = DllStructCreate($tagiconinfo)
	DllCall("user32.dll", "bool", "GetIconInfo", "handle", $hicon, "ptr", DllStructGetPtr($tinfo))
	If @error Then Return SetError(@error, @extended, 0)
	Local $aicon[6]
	$aicon[0] = True
	$aicon[1] = DllStructGetData($tinfo, "Icon") <> 0
	$aicon[2] = DllStructGetData($tinfo, "XHotSpot")
	$aicon[3] = DllStructGetData($tinfo, "YHotSpot")
	$aicon[4] = DllStructGetData($tinfo, "hMask")
	$aicon[5] = DllStructGetData($tinfo, "hColor")
	Return $aicon
EndFunc

Func _winapi_getfilesizeex($hfile)
	Local $aresult = DllCall("kernel32.dll", "bool", "GetFileSizeEx", "handle", $hfile, "int64*", 0)
	If @error Then Return SetError(@error, @extended, 0)
	Return $aresult[2]
EndFunc

Func _winapi_getlasterrormessage()
	Local $tbufferptr = DllStructCreate("ptr")
	Local $pbufferptr = DllStructGetPtr($tbufferptr)
	Local $ncount = _winapi_formatmessage(BitOR($__winapiconstant_format_message_allocate_buffer, $__winapiconstant_format_message_from_system), 0, _winapi_getlasterror(), 0, $pbufferptr, 0, 0)
	If @error Then Return SetError(@error, 0, "")
	Local $stext = ""
	Local $pbuffer = DllStructGetData($tbufferptr, 1)
	If $pbuffer Then
		If $ncount > 0 Then
			Local $tbuffer = DllStructCreate("wchar[" & ($ncount + 1) & "]", $pbuffer)
			$stext = DllStructGetData($tbuffer, 1)
		EndIf
		_winapi_localfree($pbuffer)
	EndIf
	Return $stext
EndFunc

Func _winapi_getlayeredwindowattributes($hwnd, ByRef $i_transcolor, ByRef $transparency, $ascolorref = False)
	$i_transcolor = -1
	$transparency = -1
	Local $aresult = DllCall("user32.dll", "bool", "GetLayeredWindowAttributes", "hwnd", $hwnd, "dword*", $i_transcolor, "byte*", $transparency, "dword*", 0)
	If @error Then Return SetError(@error, @extended, 0)
	If NOT $ascolorref Then
		$aresult[2] = Hex(String($aresult[2]), 6)
		$aresult[2] = "0x" & StringMid($aresult[2], 5, 2) & StringMid($aresult[2], 3, 2) & StringMid($aresult[2], 1, 2)
	EndIf
	$i_transcolor = $aresult[2]
	$transparency = $aresult[3]
	Return $aresult[4]
EndFunc

Func _winapi_getmodulehandle($smodulename)
	Local $smodulenametype = "wstr"
	If $smodulename = "" Then
		$smodulename = 0
		$smodulenametype = "ptr"
	EndIf
	Local $aresult = DllCall("kernel32.dll", "handle", "GetModuleHandleW", $smodulenametype, $smodulename)
	If @error Then Return SetError(@error, @extended, 0)
	Return $aresult[0]
EndFunc

Func _winapi_getmousepos($ftoclient = False, $hwnd = 0)
	Local $imode = Opt("MouseCoordMode", 1)
	Local $apos = MouseGetPos()
	Opt("MouseCoordMode", $imode)
	Local $tpoint = DllStructCreate($tagpoint)
	DllStructSetData($tpoint, "X", $apos[0])
	DllStructSetData($tpoint, "Y", $apos[1])
	If $ftoclient Then
		_winapi_screentoclient($hwnd, $tpoint)
		If @error Then Return SetError(@error, @extended, 0)
	EndIf
	Return $tpoint
EndFunc

Func _winapi_getmouseposx($ftoclient = False, $hwnd = 0)
	Local $tpoint = _winapi_getmousepos($ftoclient, $hwnd)
	If @error Then Return SetError(@error, @extended, 0)
	Return DllStructGetData($tpoint, "X")
EndFunc

Func _winapi_getmouseposy($ftoclient = False, $hwnd = 0)
	Local $tpoint = _winapi_getmousepos($ftoclient, $hwnd)
	If @error Then Return SetError(@error, @extended, 0)
	Return DllStructGetData($tpoint, "Y")
EndFunc

Func _winapi_getobject($hobject, $isize, $pobject)
	Local $aresult = DllCall("gdi32.dll", "int", "GetObject", "handle", $hobject, "int", $isize, "ptr", $pobject)
	If @error Then Return SetError(@error, @extended, 0)
	Return $aresult[0]
EndFunc

Func _winapi_getopenfilename($stitle = "", $sfilter = "All files (*.*)", $sinitaldir = ".", $sdefaultfile = "", $sdefaultext = "", $ifilterindex = 1, $iflags = 0, $iflagsex = 0, $hwndowner = 0)
	Local $ipathlen = 4096
	Local $inulls = 0
	Local $tofn = DllStructCreate($tagopenfilename)
	Local $afiles[1] = [0]
	Local $iflag = $iflags
	Local $asflines = StringSplit($sfilter, "|")
	Local $asfilter[$asflines[0] * 2 + 1]
	Local $istart, $ifinal, $stfilter
	$asfilter[0] = $asflines[0] * 2
	For $i = 1 To $asflines[0]
		$istart = StringInStr($asflines[$i], "(", 0, 1)
		$ifinal = StringInStr($asflines[$i], ")", 0, -1)
		$asfilter[$i * 2 - 1] = StringStripWS(StringLeft($asflines[$i], $istart - 1), 3)
		$asfilter[$i * 2] = StringStripWS(StringTrimRight(StringTrimLeft($asflines[$i], $istart), StringLen($asflines[$i]) - $ifinal + 1), 3)
		$stfilter &= "wchar[" & StringLen($asfilter[$i * 2 - 1]) + 1 & "];wchar[" & StringLen($asfilter[$i * 2]) + 1 & "];"
	Next
	Local $ttitle = DllStructCreate("wchar Title[" & StringLen($stitle) + 1 & "]")
	Local $tinitialdir = DllStructCreate("wchar InitDir[" & StringLen($sinitaldir) + 1 & "]")
	Local $tfilter = DllStructCreate($stfilter & "wchar")
	Local $tpath = DllStructCreate("wchar Path[" & $ipathlen & "]")
	Local $textn = DllStructCreate("wchar Extension[" & StringLen($sdefaultext) + 1 & "]")
	For $i = 1 To $asfilter[0]
		DllStructSetData($tfilter, $i, $asfilter[$i])
	Next
	DllStructSetData($ttitle, "Title", $stitle)
	DllStructSetData($tinitialdir, "InitDir", $sinitaldir)
	DllStructSetData($tpath, "Path", $sdefaultfile)
	DllStructSetData($textn, "Extension", $sdefaultext)
	DllStructSetData($tofn, "StructSize", DllStructGetSize($tofn))
	DllStructSetData($tofn, "hwndOwner", $hwndowner)
	DllStructSetData($tofn, "lpstrFilter", DllStructGetPtr($tfilter))
	DllStructSetData($tofn, "nFilterIndex", $ifilterindex)
	DllStructSetData($tofn, "lpstrFile", DllStructGetPtr($tpath))
	DllStructSetData($tofn, "nMaxFile", $ipathlen)
	DllStructSetData($tofn, "lpstrInitialDir", DllStructGetPtr($tinitialdir))
	DllStructSetData($tofn, "lpstrTitle", DllStructGetPtr($ttitle))
	DllStructSetData($tofn, "Flags", $iflag)
	DllStructSetData($tofn, "lpstrDefExt", DllStructGetPtr($textn))
	DllStructSetData($tofn, "FlagsEx", $iflagsex)
	DllCall("comdlg32.dll", "bool", "GetOpenFileNameW", "ptr", DllStructGetPtr($tofn))
	If @error Then Return SetError(@error, @extended, $afiles)
	If BitAND($iflags, $ofn_allowmultiselect) = $ofn_allowmultiselect AND BitAND($iflags, $ofn_explorer) = $ofn_explorer Then
		For $x = 1 To $ipathlen
			If DllStructGetData($tpath, "Path", $x) = Chr(0) Then
				DllStructSetData($tpath, "Path", "|", $x)
				$inulls += 1
			Else
				$inulls = 0
			EndIf
			If $inulls = 2 Then ExitLoop 
		Next
		DllStructSetData($tpath, "Path", Chr(0), $x - 1)
		$afiles = StringSplit(DllStructGetData($tpath, "Path"), "|")
		If $afiles[0] = 1 Then Return __winapi_parsefiledialogpath(DllStructGetData($tpath, "Path"))
		Return StringSplit(DllStructGetData($tpath, "Path"), "|")
	ElseIf BitAND($iflags, $ofn_allowmultiselect) = $ofn_allowmultiselect Then
		$afiles = StringSplit(DllStructGetData($tpath, "Path"), " ")
		If $afiles[0] = 1 Then Return __winapi_parsefiledialogpath(DllStructGetData($tpath, "Path"))
		Return StringSplit(StringReplace(DllStructGetData($tpath, "Path"), " ", "|"), "|")
	Else
		Return __winapi_parsefiledialogpath(DllStructGetData($tpath, "Path"))
	EndIf
EndFunc

Func _winapi_getoverlappedresult($hfile, $poverlapped, ByRef $ibytes, $fwait = False)
	Local $aresult = DllCall("kernel32.dll", "bool", "GetOverlappedResult", "handle", $hfile, "ptr", $poverlapped, "dword*", 0, "bool", $fwait)
	If @error Then Return SetError(@error, @extended, False)
	$ibytes = $aresult[3]
	Return $aresult[0]
EndFunc

Func _winapi_getparent($hwnd)
	Local $aresult = DllCall("user32.dll", "hwnd", "GetParent", "hwnd", $hwnd)
	If @error Then Return SetError(@error, @extended, 0)
	Return $aresult[0]
EndFunc

Func _winapi_getprocessaffinitymask($hprocess)
	Local $aresult = DllCall("kernel32.dll", "bool", "GetProcessAffinityMask", "handle", $hprocess, "dword_ptr*", 0, "dword_ptr*", 0)
	If @error Then Return SetError(@error, @extended, 0)
	Local $amask[3]
	$amask[0] = True
	$amask[1] = $aresult[2]
	$amask[2] = $aresult[3]
	Return $amask
EndFunc

Func _winapi_getsavefilename($stitle = "", $sfilter = "All files (*.*)", $sinitaldir = ".", $sdefaultfile = "", $sdefaultext = "", $ifilterindex = 1, $iflags = 0, $iflagsex = 0, $hwndowner = 0)
	Local $ipathlen = 4096
	Local $tofn = DllStructCreate($tagopenfilename)
	Local $afiles[1] = [0]
	Local $iflag = $iflags
	Local $asflines = StringSplit($sfilter, "|")
	Local $asfilter[$asflines[0] * 2 + 1]
	Local $istart, $ifinal, $stfilter
	$asfilter[0] = $asflines[0] * 2
	For $i = 1 To $asflines[0]
		$istart = StringInStr($asflines[$i], "(", 0, 1)
		$ifinal = StringInStr($asflines[$i], ")", 0, -1)
		$asfilter[$i * 2 - 1] = StringStripWS(StringLeft($asflines[$i], $istart - 1), 3)
		$asfilter[$i * 2] = StringStripWS(StringTrimRight(StringTrimLeft($asflines[$i], $istart), StringLen($asflines[$i]) - $ifinal + 1), 3)
		$stfilter &= "wchar[" & StringLen($asfilter[$i * 2 - 1]) + 1 & "];wchar[" & StringLen($asfilter[$i * 2]) + 1 & "];"
	Next
	Local $ttitle = DllStructCreate("wchar Title[" & StringLen($stitle) + 1 & "]")
	Local $tinitialdir = DllStructCreate("wchar InitDir[" & StringLen($sinitaldir) + 1 & "]")
	Local $tfilter = DllStructCreate($stfilter & "wchar")
	Local $tpath = DllStructCreate("wchar Path[" & $ipathlen & "]")
	Local $textn = DllStructCreate("wchar Extension[" & StringLen($sdefaultext) + 1 & "]")
	For $i = 1 To $asfilter[0]
		DllStructSetData($tfilter, $i, $asfilter[$i])
	Next
	DllStructSetData($ttitle, "Title", $stitle)
	DllStructSetData($tinitialdir, "InitDir", $sinitaldir)
	DllStructSetData($tpath, "Path", $sdefaultfile)
	DllStructSetData($textn, "Extension", $sdefaultext)
	DllStructSetData($tofn, "StructSize", DllStructGetSize($tofn))
	DllStructSetData($tofn, "hwndOwner", $hwndowner)
	DllStructSetData($tofn, "lpstrFilter", DllStructGetPtr($tfilter))
	DllStructSetData($tofn, "nFilterIndex", $ifilterindex)
	DllStructSetData($tofn, "lpstrFile", DllStructGetPtr($tpath))
	DllStructSetData($tofn, "nMaxFile", $ipathlen)
	DllStructSetData($tofn, "lpstrInitialDir", DllStructGetPtr($tinitialdir))
	DllStructSetData($tofn, "lpstrTitle", DllStructGetPtr($ttitle))
	DllStructSetData($tofn, "Flags", $iflag)
	DllStructSetData($tofn, "lpstrDefExt", DllStructGetPtr($textn))
	DllStructSetData($tofn, "FlagsEx", $iflagsex)
	DllCall("comdlg32.dll", "bool", "GetSaveFileNameW", "ptr", DllStructGetPtr($tofn))
	If @error Then Return SetError(@error, @extended, $afiles)
	Return __winapi_parsefiledialogpath(DllStructGetData($tpath, "Path"))
EndFunc

Func _winapi_getstockobject($iobject)
	Local $aresult = DllCall("gdi32.dll", "handle", "GetStockObject", "int", $iobject)
	If @error Then Return SetError(@error, @extended, 0)
	Return $aresult[0]
EndFunc

Func _winapi_getstdhandle($istdhandle)
	If $istdhandle < 0 OR $istdhandle > 2 Then Return SetError(2, 0, -1)
	Local Const $ahandle[3] = [-10, -11, -12]
	Local $aresult = DllCall("kernel32.dll", "handle", "GetStdHandle", "dword", $ahandle[$istdhandle])
	If @error Then Return SetError(@error, @extended, -1)
	Return $aresult[0]
EndFunc

Func _winapi_getsyscolor($iindex)
	Local $aresult = DllCall("user32.dll", "dword", "GetSysColor", "int", $iindex)
	If @error Then Return SetError(@error, @extended, 0)
	Return $aresult[0]
EndFunc

Func _winapi_getsyscolorbrush($iindex)
	Local $aresult = DllCall("user32.dll", "handle", "GetSysColorBrush", "int", $iindex)
	If @error Then Return SetError(@error, @extended, 0)
	Return $aresult[0]
EndFunc

Func _winapi_getsystemmetrics($iindex)
	Local $aresult = DllCall("user32.dll", "int", "GetSystemMetrics", "int", $iindex)
	If @error Then Return SetError(@error, @extended, 0)
	Return $aresult[0]
EndFunc

Func _winapi_gettextextentpoint32($hdc, $stext)
	Local $tsize = DllStructCreate($tagsize)
	Local $isize = StringLen($stext)
	DllCall("gdi32.dll", "bool", "GetTextExtentPoint32W", "handle", $hdc, "wstr", $stext, "int", $isize, "ptr", DllStructGetPtr($tsize))
	If @error Then Return SetError(@error, @extended, 0)
	Return $tsize
EndFunc

Func _winapi_getwindow($hwnd, $icmd)
	Local $aresult = DllCall("user32.dll", "hwnd", "GetWindow", "hwnd", $hwnd, "uint", $icmd)
	If @error Then Return SetError(@error, @extended, 0)
	Return $aresult[0]
EndFunc

Func _winapi_getwindowdc($hwnd)
	Local $aresult = DllCall("user32.dll", "handle", "GetWindowDC", "hwnd", $hwnd)
	If @error Then Return SetError(@error, @extended, 0)
	Return $aresult[0]
EndFunc

Func _winapi_getwindowheight($hwnd)
	Local $trect = _winapi_getwindowrect($hwnd)
	If @error Then Return SetError(@error, @extended, 0)
	Return DllStructGetData($trect, "Bottom") - DllStructGetData($trect, "Top")
EndFunc

Func _winapi_getwindowlong($hwnd, $iindex)
	Local $sfuncname = "GetWindowLongW"
	If @AutoItX64 Then $sfuncname = "GetWindowLongPtrW"
	Local $aresult = DllCall("user32.dll", "long_ptr", $sfuncname, "hwnd", $hwnd, "int", $iindex)
	If @error Then Return SetError(@error, @extended, 0)
	Return $aresult[0]
EndFunc

Func _winapi_getwindowplacement($hwnd)
	Local $twindowplacement = DllStructCreate($tagwindowplacement)
	DllStructSetData($twindowplacement, "length", DllStructGetSize($twindowplacement))
	Local $pwindowplacement = DllStructGetPtr($twindowplacement)
	DllCall("user32.dll", "bool", "GetWindowPlacement", "hwnd", $hwnd, "ptr", $pwindowplacement)
	If @error Then Return SetError(@error, @extended, 0)
	Return $twindowplacement
EndFunc

Func _winapi_getwindowrect($hwnd)
	Local $trect = DllStructCreate($tagrect)
	DllCall("user32.dll", "bool", "GetWindowRect", "hwnd", $hwnd, "ptr", DllStructGetPtr($trect))
	If @error Then Return SetError(@error, @extended, 0)
	Return $trect
EndFunc

Func _winapi_getwindowrgn($hwnd, $hrgn)
	Local $aresult = DllCall("user32.dll", "int", "GetWindowRgn", "hwnd", $hwnd, "handle", $hrgn)
	If @error Then Return SetError(@error, @extended, 0)
	Return $aresult[0]
EndFunc

Func _winapi_getwindowtext($hwnd)
	Local $aresult = DllCall("user32.dll", "int", "GetWindowTextW", "hwnd", $hwnd, "wstr", "", "int", 4096)
	If @error Then Return SetError(@error, @extended, "")
	Return SetExtended($aresult[0], $aresult[2])
EndFunc

Func _winapi_getwindowthreadprocessid($hwnd, ByRef $ipid)
	Local $aresult = DllCall("user32.dll", "dword", "GetWindowThreadProcessId", "hwnd", $hwnd, "dword*", 0)
	If @error Then Return SetError(@error, @extended, 0)
	$ipid = $aresult[2]
	Return $aresult[0]
EndFunc

Func _winapi_getwindowwidth($hwnd)
	Local $trect = _winapi_getwindowrect($hwnd)
	If @error Then Return SetError(@error, @extended, 0)
	Return DllStructGetData($trect, "Right") - DllStructGetData($trect, "Left")
EndFunc

Func _winapi_getxyfrompoint(ByRef $tpoint, ByRef $ix, ByRef $iy)
	$ix = DllStructGetData($tpoint, "X")
	$iy = DllStructGetData($tpoint, "Y")
EndFunc

Func _winapi_globalmemorystatus()
	Local $tmem = DllStructCreate($tagmemorystatusex)
	Local $pmem = DllStructGetPtr($tmem)
	Local $imem = DllStructGetSize($tmem)
	DllStructSetData($tmem, 1, $imem)
	DllCall("kernel32.dll", "none", "GlobalMemoryStatusEx", "ptr", $pmem)
	If @error Then Return SetError(@error, @extended, 0)
	Local $amem[7]
	$amem[0] = DllStructGetData($tmem, 2)
	$amem[1] = DllStructGetData($tmem, 3)
	$amem[2] = DllStructGetData($tmem, 4)
	$amem[3] = DllStructGetData($tmem, 5)
	$amem[4] = DllStructGetData($tmem, 6)
	$amem[5] = DllStructGetData($tmem, 7)
	$amem[6] = DllStructGetData($tmem, 8)
	Return $amem
EndFunc

Func _winapi_guidfromstring($sguid)
	Local $tguid = DllStructCreate($tagguid)
	_winapi_guidfromstringex($sguid, DllStructGetPtr($tguid))
	If @error Then Return SetError(@error, @extended, 0)
	Return $tguid
EndFunc

Func _winapi_guidfromstringex($sguid, $pguid)
	Local $aresult = DllCall("ole32.dll", "long", "CLSIDFromString", "wstr", $sguid, "ptr", $pguid)
	If @error Then Return SetError(@error, @extended, False)
	Return $aresult[0]
EndFunc

Func _winapi_hiword($ilong)
	Return BitShift($ilong, 16)
EndFunc

Func _winapi_inprocess($hwnd, ByRef $hlastwnd)
	If $hwnd = $hlastwnd Then Return True
	For $ii = $__gainprocess_winapi[0][0] To 1 Step -1
		If $hwnd = $__gainprocess_winapi[$ii][0] Then
			If $__gainprocess_winapi[$ii][1] Then
				$hlastwnd = $hwnd
				Return True
			Else
				Return False
			EndIf
		EndIf
	Next
	Local $iprocessid
	_winapi_getwindowthreadprocessid($hwnd, $iprocessid)
	Local $icount = $__gainprocess_winapi[0][0] + 1
	If $icount >= 64 Then $icount = 1
	$__gainprocess_winapi[0][0] = $icount
	$__gainprocess_winapi[$icount][0] = $hwnd
	$__gainprocess_winapi[$icount][1] = ($iprocessid = @AutoItPID)
	Return $__gainprocess_winapi[$icount][1]
EndFunc

Func _winapi_inttofloat($iint)
	Local $tint = DllStructCreate("int")
	Local $tfloat = DllStructCreate("float", DllStructGetPtr($tint))
	DllStructSetData($tint, 1, $iint)
	Return DllStructGetData($tfloat, 1)
EndFunc

Func _winapi_isclassname($hwnd, $sclassname)
	Local $sseparator = Opt("GUIDataSeparatorChar")
	Local $aclassname = StringSplit($sclassname, $sseparator)
	If NOT IsHWnd($hwnd) Then $hwnd = GUICtrlGetHandle($hwnd)
	Local $sclasscheck = _winapi_getclassname($hwnd)
	For $x = 1 To UBound($aclassname) - 1
		If StringUpper(StringMid($sclasscheck, 1, StringLen($aclassname[$x]))) = StringUpper($aclassname[$x]) Then Return True
	Next
	Return False
EndFunc

Func _winapi_iswindow($hwnd)
	Local $aresult = DllCall("user32.dll", "bool", "IsWindow", "hwnd", $hwnd)
	If @error Then Return SetError(@error, @extended, 0)
	Return $aresult[0]
EndFunc

Func _winapi_iswindowvisible($hwnd)
	Local $aresult = DllCall("user32.dll", "bool", "IsWindowVisible", "hwnd", $hwnd)
	If @error Then Return SetError(@error, @extended, 0)
	Return $aresult[0]
EndFunc

Func _winapi_invalidaterect($hwnd, $trect = 0, $ferase = True)
	Local $prect = 0
	If IsDllStruct($trect) Then $prect = DllStructGetPtr($trect)
	Local $aresult = DllCall("user32.dll", "bool", "InvalidateRect", "hwnd", $hwnd, "ptr", $prect, "bool", $ferase)
	If @error Then Return SetError(@error, @extended, False)
	Return $aresult[0]
EndFunc

Func _winapi_lineto($hdc, $ix, $iy)
	Local $aresult = DllCall("gdi32.dll", "bool", "LineTo", "handle", $hdc, "int", $ix, "int", $iy)
	If @error Then Return SetError(@error, @extended, False)
	Return $aresult[0]
EndFunc

Func _winapi_loadbitmap($hinstance, $sbitmap)
	Local $sbitmaptype = "int"
	If IsString($sbitmap) Then $sbitmaptype = "wstr"
	Local $aresult = DllCall("user32.dll", "handle", "LoadBitmapW", "handle", $hinstance, $sbitmaptype, $sbitmap)
	If @error Then Return SetError(@error, @extended, 0)
	Return $aresult[0]
EndFunc

Func _winapi_loadimage($hinstance, $simage, $itype, $ixdesired, $iydesired, $iload)
	Local $aresult, $simagetype = "int"
	If IsString($simage) Then $simagetype = "wstr"
	$aresult = DllCall("user32.dll", "handle", "LoadImageW", "handle", $hinstance, $simagetype, $simage, "uint", $itype, "int", $ixdesired, "int", $iydesired, "uint", $iload)
	If @error Then Return SetError(@error, @extended, 0)
	Return $aresult[0]
EndFunc

Func _winapi_loadlibrary($sfilename)
	Local $aresult = DllCall("kernel32.dll", "handle", "LoadLibraryW", "wstr", $sfilename)
	If @error Then Return SetError(@error, @extended, 0)
	Return $aresult[0]
EndFunc

Func _winapi_loadlibraryex($sfilename, $iflags = 0)
	Local $aresult = DllCall("kernel32.dll", "handle", "LoadLibraryExW", "wstr", $sfilename, "ptr", 0, "dword", $iflags)
	If @error Then Return SetError(@error, @extended, 0)
	Return $aresult[0]
EndFunc

Func _winapi_loadshell32icon($iiconid)
	Local $ticons = DllStructCreate("ptr Data")
	Local $picons = DllStructGetPtr($ticons)
	Local $iicons = _winapi_extracticonex("shell32.dll", $iiconid, 0, $picons, 1)
	If @error Then Return SetError(@error, @extended, 0)
	If $iicons <= 0 Then Return SetError(1, 0, 0)
	Return DllStructGetData($ticons, "Data")
EndFunc

Func _winapi_loadstring($hinstance, $istringid)
	Local $aresult = DllCall("user32.dll", "int", "LoadStringW", "handle", $hinstance, "uint", $istringid, "wstr", "", "int", 4096)
	If @error Then Return SetError(@error, @extended, "")
	Return SetExtended($aresult[0], $aresult[3])
EndFunc

Func _winapi_localfree($hmem)
	Local $aresult = DllCall("kernel32.dll", "handle", "LocalFree", "handle", $hmem)
	If @error Then Return SetError(@error, @extended, False)
	Return $aresult[0]
EndFunc

Func _winapi_loword($ilong)
	Return BitAND($ilong, 65535)
EndFunc

Func _winapi_makelangid($lgidprimary, $lgidsub)
	Return BitOR(BitShift($lgidsub, -10), $lgidprimary)
EndFunc

Func _winapi_makelcid($lgid, $srtid)
	Return BitOR(BitShift($srtid, -16), $lgid)
EndFunc

Func _winapi_makelong($ilo, $ihi)
	Return BitOR(BitShift($ihi, -16), BitAND($ilo, 65535))
EndFunc

Func _winapi_makeqword($lodword, $hidword)
	Local $tint64 = DllStructCreate("uint64")
	Local $tdwords = DllStructCreate("dword;dword", DllStructGetPtr($tint64))
	DllStructSetData($tdwords, 1, $lodword)
	DllStructSetData($tdwords, 2, $hidword)
	Return DllStructGetData($tint64, 1)
EndFunc

Func _winapi_messagebeep($itype = 1)
	Local $isound
	Switch $itype
		Case 1
			$isound = 0
		Case 2
			$isound = 16
		Case 3
			$isound = 32
		Case 4
			$isound = 48
		Case 5
			$isound = 64
		Case Else
			$isound = -1
	EndSwitch
	Local $aresult = DllCall("user32.dll", "bool", "MessageBeep", "uint", $isound)
	If @error Then Return SetError(@error, @extended, False)
	Return $aresult[0]
EndFunc

Func _winapi_msgbox($iflags, $stitle, $stext)
	BlockInput(0)
	MsgBox($iflags, $stitle, $stext & "      ")
EndFunc

Func _winapi_mouse_event($iflags, $ix = 0, $iy = 0, $idata = 0, $iextrainfo = 0)
	DllCall("user32.dll", "none", "mouse_event", "dword", $iflags, "dword", $ix, "dword", $iy, "dword", $idata, "ulong_ptr", $iextrainfo)
	If @error Then Return SetError(@error, @extended)
EndFunc

Func _winapi_moveto($hdc, $ix, $iy)
	Local $aresult = DllCall("gdi32.dll", "bool", "MoveToEx", "handle", $hdc, "int", $ix, "int", $iy, "ptr", 0)
	If @error Then Return SetError(@error, @extended, False)
	Return $aresult[0]
EndFunc

Func _winapi_movewindow($hwnd, $ix, $iy, $iwidth, $iheight, $frepaint = True)
	Local $aresult = DllCall("user32.dll", "bool", "MoveWindow", "hwnd", $hwnd, "int", $ix, "int", $iy, "int", $iwidth, "int", $iheight, "bool", $frepaint)
	If @error Then Return SetError(@error, @extended, False)
	Return $aresult[0]
EndFunc

Func _winapi_muldiv($inumber, $inumerator, $idenominator)
	Local $aresult = DllCall("kernel32.dll", "int", "MulDiv", "int", $inumber, "int", $inumerator, "int", $idenominator)
	If @error Then Return SetError(@error, @extended, -1)
	Return $aresult[0]
EndFunc

Func _winapi_multibytetowidechar($stext, $icodepage = 0, $iflags = 0, $bretstring = False)
	Local $stexttype = "ptr", $ptext = $stext
	If IsDllStruct($stext) Then
		$ptext = DllStructGetPtr($stext)
	Else
		If NOT IsPtr($stext) Then $stexttype = "STR"
	EndIf
	Local $aresult = DllCall("kernel32.dll", "int", "MultiByteToWideChar", "uint", $icodepage, "dword", $iflags, $stexttype, $ptext, "int", -1, "ptr", 0, "int", 0)
	If @error Then Return SetError(@error, @extended, 0)
	Local $iout = $aresult[0]
	Local $tout = DllStructCreate("wchar[" & $iout & "]")
	Local $pout = DllStructGetPtr($tout)
	$aresult = DllCall("kernel32.dll", "int", "MultiByteToWideChar", "uint", $icodepage, "dword", $iflags, $stexttype, $ptext, "int", -1, "ptr", $pout, "int", $iout)
	If @error Then Return SetError(@error, @extended, 0)
	If $bretstring Then Return DllStructGetData($tout, 1)
	Return $tout
EndFunc

Func _winapi_multibytetowidecharex($stext, $ptext, $icodepage = 0, $iflags = 0)
	Local $aresult = DllCall("kernel32.dll", "int", "MultiByteToWideChar", "uint", $icodepage, "dword", $iflags, "STR", $stext, "int", -1, "ptr", $ptext, "int", (StringLen($stext) + 1) * 2)
	If @error Then Return SetError(@error, @extended, False)
	Return $aresult[0]
EndFunc

Func _winapi_openprocess($iaccess, $finherit, $iprocessid, $fdebugpriv = False)
	Local $aresult = DllCall("kernel32.dll", "handle", "OpenProcess", "dword", $iaccess, "bool", $finherit, "dword", $iprocessid)
	If @error Then Return SetError(@error, @extended, 0)
	If $aresult[0] Then Return $aresult[0]
	If NOT $fdebugpriv Then Return 0
	Local $htoken = _security__openthreadtokenex(BitOR($token_adjust_privileges, $token_query))
	If @error Then Return SetError(@error, @extended, 0)
	_security__setprivilege($htoken, "SeDebugPrivilege", True)
	Local $ierror = @error
	Local $ilasterror = @extended
	Local $iret = 0
	If NOT @error Then
		$aresult = DllCall("kernel32.dll", "handle", "OpenProcess", "dword", $iaccess, "bool", $finherit, "dword", $iprocessid)
		$ierror = @error
		$ilasterror = @extended
		If $aresult[0] Then $iret = $aresult[0]
		_security__setprivilege($htoken, "SeDebugPrivilege", False)
		If @error Then
			$ierror = @error
			$ilasterror = @extended
		EndIf
	EndIf
	_winapi_closehandle($htoken)
	Return SetError($ierror, $ilasterror, $iret)
EndFunc

Func __winapi_parsefiledialogpath($spath)
	Local $afiles[3]
	$afiles[0] = 2
	Local $stemp = StringMid($spath, 1, StringInStr($spath, "\", 0, -1) - 1)
	$afiles[1] = $stemp
	$afiles[2] = StringMid($spath, StringInStr($spath, "\", 0, -1) + 1)
	Return $afiles
EndFunc

Func _winapi_pathfindonpath(Const $szfile, $aextrapaths = "", Const $szpathdelimiter = @LF)
	Local $iextracount = 0
	If IsString($aextrapaths) Then
		If StringLen($aextrapaths) Then
			$aextrapaths = StringSplit($aextrapaths, $szpathdelimiter, 1 + 2)
			$iextracount = UBound($aextrapaths, 1)
		EndIf
	ElseIf IsArray($aextrapaths) Then
		$iextracount = UBound($aextrapaths)
	EndIf
	Local $tpaths, $tpathptrs
	If $iextracount Then
		Local $szstruct = ""
		For $path In $aextrapaths
			$szstruct &= "wchar[" & StringLen($path) + 1 & "];"
		Next
		$tpaths = DllStructCreate($szstruct)
		$tpathptrs = DllStructCreate("ptr[" & $iextracount + 1 & "]")
		For $i = 1 To $iextracount
			DllStructSetData($tpaths, $i, $aextrapaths[$i - 1])
			DllStructSetData($tpathptrs, 1, DllStructGetPtr($tpaths, $i), $i)
		Next
		DllStructSetData($tpathptrs, 1, Ptr(0), $iextracount + 1)
	EndIf
	Local $aresult = DllCall("shlwapi.dll", "bool", "PathFindOnPathW", "wstr", $szfile, "ptr", DllStructGetPtr($tpathptrs))
	If @error Then Return SetError(@error, @extended, False)
	If $aresult[0] = 0 Then Return SetError(1, 0, $szfile)
	Return $aresult[1]
EndFunc

Func _winapi_pointfromrect(ByRef $trect, $fcenter = True)
	Local $ix1 = DllStructGetData($trect, "Left")
	Local $iy1 = DllStructGetData($trect, "Top")
	Local $ix2 = DllStructGetData($trect, "Right")
	Local $iy2 = DllStructGetData($trect, "Bottom")
	If $fcenter Then
		$ix1 = $ix1 + (($ix2 - $ix1) / 2)
		$iy1 = $iy1 + (($iy2 - $iy1) / 2)
	EndIf
	Local $tpoint = DllStructCreate($tagpoint)
	DllStructSetData($tpoint, "X", $ix1)
	DllStructSetData($tpoint, "Y", $iy1)
	Return $tpoint
EndFunc

Func _winapi_postmessage($hwnd, $imsg, $iwparam, $ilparam)
	Local $aresult = DllCall("user32.dll", "bool", "PostMessage", "hwnd", $hwnd, "uint", $imsg, "wparam", $iwparam, "lparam", $ilparam)
	If @error Then Return SetError(@error, @extended, False)
	Return $aresult[0]
EndFunc

Func _winapi_primarylangid($lgid)
	Return BitAND($lgid, 1023)
EndFunc

Func _winapi_ptinrect(ByRef $trect, ByRef $tpoint)
	Local $ix = DllStructGetData($tpoint, "X")
	Local $iy = DllStructGetData($tpoint, "Y")
	Local $aresult = DllCall("user32.dll", "bool", "PtInRect", "ptr", DllStructGetPtr($trect), "long", $ix, "long", $iy)
	If @error Then Return SetError(@error, @extended, False)
	Return $aresult[0]
EndFunc

Func _winapi_readfile($hfile, $pbuffer, $itoread, ByRef $iread, $poverlapped = 0)
	Local $aresult = DllCall("kernel32.dll", "bool", "ReadFile", "handle", $hfile, "ptr", $pbuffer, "dword", $itoread, "dword*", 0, "ptr", $poverlapped)
	If @error Then Return SetError(@error, @extended, False)
	$iread = $aresult[4]
	Return $aresult[0]
EndFunc

Func _winapi_readprocessmemory($hprocess, $pbaseaddress, $pbuffer, $isize, ByRef $iread)
	Local $aresult = DllCall("kernel32.dll", "bool", "ReadProcessMemory", "handle", $hprocess, "ptr", $pbaseaddress, "ptr", $pbuffer, "ulong_ptr", $isize, "ulong_ptr*", 0)
	If @error Then Return SetError(@error, @extended, False)
	$iread = $aresult[5]
	Return $aresult[0]
EndFunc

Func _winapi_rectisempty(ByRef $trect)
	Return (DllStructGetData($trect, "Left") = 0) AND (DllStructGetData($trect, "Top") = 0) AND (DllStructGetData($trect, "Right") = 0) AND (DllStructGetData($trect, "Bottom") = 0)
EndFunc

Func _winapi_redrawwindow($hwnd, $trect = 0, $hregion = 0, $iflags = 5)
	Local $prect = 0
	If $trect <> 0 Then $prect = DllStructGetPtr($trect)
	Local $aresult = DllCall("user32.dll", "bool", "RedrawWindow", "hwnd", $hwnd, "ptr", $prect, "handle", $hregion, "uint", $iflags)
	If @error Then Return SetError(@error, @extended, False)
	Return $aresult[0]
EndFunc

Func _winapi_registerwindowmessage($smessage)
	Local $aresult = DllCall("user32.dll", "uint", "RegisterWindowMessageW", "wstr", $smessage)
	If @error Then Return SetError(@error, @extended, 0)
	Return $aresult[0]
EndFunc

Func _winapi_releasecapture()
	Local $aresult = DllCall("user32.dll", "bool", "ReleaseCapture")
	If @error Then Return SetError(@error, @extended, False)
	Return $aresult[0]
EndFunc

Func _winapi_releasedc($hwnd, $hdc)
	Local $aresult = DllCall("user32.dll", "int", "ReleaseDC", "hwnd", $hwnd, "handle", $hdc)
	If @error Then Return SetError(@error, @extended, False)
	Return $aresult[0]
EndFunc

Func _winapi_screentoclient($hwnd, ByRef $tpoint)
	Local $aresult = DllCall("user32.dll", "bool", "ScreenToClient", "hwnd", $hwnd, "ptr", DllStructGetPtr($tpoint))
	If @error Then Return SetError(@error, @extended, False)
	Return $aresult[0]
EndFunc

Func _winapi_selectobject($hdc, $hgdiobj)
	Local $aresult = DllCall("gdi32.dll", "handle", "SelectObject", "handle", $hdc, "handle", $hgdiobj)
	If @error Then Return SetError(@error, @extended, False)
	Return $aresult[0]
EndFunc

Func _winapi_setbkcolor($hdc, $icolor)
	Local $aresult = DllCall("gdi32.dll", "INT", "SetBkColor", "handle", $hdc, "dword", $icolor)
	If @error Then Return SetError(@error, @extended, -1)
	Return $aresult[0]
EndFunc

Func _winapi_setbkmode($hdc, $ibkmode)
	Local $aresult = DllCall("gdi32.dll", "int", "SetBkMode", "handle", $hdc, "int", $ibkmode)
	If @error Then Return SetError(@error, @extended, 0)
	Return $aresult[0]
EndFunc

Func _winapi_setcapture($hwnd)
	Local $aresult = DllCall("user32.dll", "hwnd", "SetCapture", "hwnd", $hwnd)
	If @error Then Return SetError(@error, @extended, 0)
	Return $aresult[0]
EndFunc

Func _winapi_setcursor($hcursor)
	Local $aresult = DllCall("user32.dll", "handle", "SetCursor", "handle", $hcursor)
	If @error Then Return SetError(@error, @extended, 0)
	Return $aresult[0]
EndFunc

Func _winapi_setdefaultprinter($sprinter)
	Local $aresult = DllCall("winspool.drv", "bool", "SetDefaultPrinterW", "wstr", $sprinter)
	If @error Then Return SetError(@error, @extended, False)
	Return $aresult[0]
EndFunc

Func _winapi_setdibits($hdc, $hbmp, $istartscan, $iscanlines, $pbits, $pbmi, $icoloruse = 0)
	Local $aresult = DllCall("gdi32.dll", "int", "SetDIBits", "handle", $hdc, "handle", $hbmp, "uint", $istartscan, "uint", $iscanlines, "ptr", $pbits, "ptr", $pbmi, "uint", $icoloruse)
	If @error Then Return SetError(@error, @extended, False)
	Return $aresult[0]
EndFunc

Func _winapi_setendoffile($hfile)
	Local $aresult = DllCall("kernel32.dll", "bool", "SetEndOfFile", "handle", $hfile)
	If @error Then Return SetError(@error, @extended, False)
	Return $aresult[0]
EndFunc

Func _winapi_setevent($hevent)
	Local $aresult = DllCall("kernel32.dll", "bool", "SetEvent", "handle", $hevent)
	If @error Then Return SetError(@error, @extended, False)
	Return $aresult[0]
EndFunc

Func _winapi_setfilepointer($hfile, $ipos, $imethod = 0)
	Local $aresult = DllCall("kernel32.dll", "INT", "SetFilePointer", "handle", $hfile, "long", $ipos, "ptr", 0, "long", $imethod)
	If @error Then Return SetError(@error, @extended, -1)
	Return $aresult[0]
EndFunc

Func _winapi_setfocus($hwnd)
	Local $aresult = DllCall("user32.dll", "hwnd", "SetFocus", "hwnd", $hwnd)
	If @error Then Return SetError(@error, @extended, 0)
	Return $aresult[0]
EndFunc

Func _winapi_setfont($hwnd, $hfont, $fredraw = True)
	_sendmessage($hwnd, $__winapiconstant_wm_setfont, $hfont, $fredraw, 0, "hwnd")
EndFunc

Func _winapi_sethandleinformation($hobject, $imask, $iflags)
	Local $aresult = DllCall("kernel32.dll", "bool", "SetHandleInformation", "handle", $hobject, "dword", $imask, "dword", $iflags)
	If @error Then Return SetError(@error, @extended, False)
	Return $aresult[0]
EndFunc

Func _winapi_setlayeredwindowattributes($hwnd, $i_transcolor, $transparency = 255, $dwflags = 3, $iscolorref = False)
	If $dwflags = Default OR $dwflags = "" OR $dwflags < 0 Then $dwflags = 3
	If NOT $iscolorref Then
		$i_transcolor = Hex(String($i_transcolor), 6)
		$i_transcolor = Execute("0x00" & StringMid($i_transcolor, 5, 2) & StringMid($i_transcolor, 3, 2) & StringMid($i_transcolor, 1, 2))
	EndIf
	Local $aresult = DllCall("user32.dll", "bool", "SetLayeredWindowAttributes", "hwnd", $hwnd, "dword", $i_transcolor, "byte", $transparency, "dword", $dwflags)
	If @error Then Return SetError(@error, @extended, False)
	Return $aresult[0]
EndFunc

Func _winapi_setparent($hwndchild, $hwndparent)
	Local $aresult = DllCall("user32.dll", "hwnd", "SetParent", "hwnd", $hwndchild, "hwnd", $hwndparent)
	If @error Then Return SetError(@error, @extended, 0)
	Return $aresult[0]
EndFunc

Func _winapi_setprocessaffinitymask($hprocess, $imask)
	Local $aresult = DllCall("kernel32.dll", "bool", "SetProcessAffinityMask", "handle", $hprocess, "ulong_ptr", $imask)
	If @error Then Return SetError(@error, @extended, False)
	Return $aresult[0]
EndFunc

Func _winapi_setsyscolors($velements, $vcolors)
	Local $isearray = IsArray($velements), $iscarray = IsArray($vcolors)
	Local $ielementnum
	If NOT $iscarray AND NOT $isearray Then
		$ielementnum = 1
	ElseIf $iscarray OR $isearray Then
		If NOT $iscarray OR NOT $isearray Then Return SetError(-1, -1, False)
		If UBound($velements) <> UBound($vcolors) Then Return SetError(-1, -1, False)
		$ielementnum = UBound($velements)
	EndIf
	Local $telements = DllStructCreate("int Element[" & $ielementnum & "]")
	Local $tcolors = DllStructCreate("dword NewColor[" & $ielementnum & "]")
	Local $pelements = DllStructGetPtr($telements)
	Local $pcolors = DllStructGetPtr($tcolors)
	If NOT $isearray Then
		DllStructSetData($telements, "Element", $velements, 1)
	Else
		For $x = 0 To $ielementnum - 1
			DllStructSetData($telements, "Element", $velements[$x], $x + 1)
		Next
	EndIf
	If NOT $iscarray Then
		DllStructSetData($tcolors, "NewColor", $vcolors, 1)
	Else
		For $x = 0 To $ielementnum - 1
			DllStructSetData($tcolors, "NewColor", $vcolors[$x], $x + 1)
		Next
	EndIf
	Local $aresult = DllCall("user32.dll", "bool", "SetSysColors", "int", $ielementnum, "ptr", $pelements, "ptr", $pcolors)
	If @error Then Return SetError(@error, @extended, False)
	Return $aresult[0]
EndFunc

Func _winapi_settextcolor($hdc, $icolor)
	Local $aresult = DllCall("gdi32.dll", "INT", "SetTextColor", "handle", $hdc, "dword", $icolor)
	If @error Then Return SetError(@error, @extended, -1)
	Return $aresult[0]
EndFunc

Func _winapi_setwindowlong($hwnd, $iindex, $ivalue)
	_winapi_setlasterror(0)
	Local $sfuncname = "SetWindowLongW"
	If @AutoItX64 Then $sfuncname = "SetWindowLongPtrW"
	Local $aresult = DllCall("user32.dll", "long_ptr", $sfuncname, "hwnd", $hwnd, "int", $iindex, "long_ptr", $ivalue)
	If @error Then Return SetError(@error, @extended, 0)
	Return $aresult[0]
EndFunc

Func _winapi_setwindowplacement($hwnd, $pwindowplacement)
	Local $aresult = DllCall("user32.dll", "bool", "SetWindowPlacement", "hwnd", $hwnd, "ptr", $pwindowplacement)
	If @error Then Return SetError(@error, @extended, False)
	Return $aresult[0]
EndFunc

Func _winapi_setwindowpos($hwnd, $hafter, $ix, $iy, $icx, $icy, $iflags)
	Local $aresult = DllCall("user32.dll", "bool", "SetWindowPos", "hwnd", $hwnd, "hwnd", $hafter, "int", $ix, "int", $iy, "int", $icx, "int", $icy, "uint", $iflags)
	If @error Then Return SetError(@error, @extended, False)
	Return $aresult[0]
EndFunc

Func _winapi_setwindowrgn($hwnd, $hrgn, $bredraw = True)
	Local $aresult = DllCall("user32.dll", "int", "SetWindowRgn", "hwnd", $hwnd, "handle", $hrgn, "bool", $bredraw)
	If @error Then Return SetError(@error, @extended, False)
	Return $aresult[0]
EndFunc

Func _winapi_setwindowshookex($idhook, $lpfn, $hmod, $dwthreadid = 0)
	Local $aresult = DllCall("user32.dll", "handle", "SetWindowsHookEx", "int", $idhook, "ptr", $lpfn, "handle", $hmod, "dword", $dwthreadid)
	If @error Then Return SetError(@error, @extended, 0)
	Return $aresult[0]
EndFunc

Func _winapi_setwindowtext($hwnd, $stext)
	Local $aresult = DllCall("user32.dll", "bool", "SetWindowTextW", "hwnd", $hwnd, "wstr", $stext)
	If @error Then Return SetError(@error, @extended, False)
	Return $aresult[0]
EndFunc

Func _winapi_showcursor($fshow)
	Local $aresult = DllCall("user32.dll", "int", "ShowCursor", "bool", $fshow)
	If @error Then Return SetError(@error, @extended, 0)
	Return $aresult[0]
EndFunc

Func _winapi_showerror($stext, $fexit = True)
	_winapi_msgbox(266256, "Error", $stext)
	If $fexit Then Exit 
EndFunc

Func _winapi_showmsg($stext)
	_winapi_msgbox(64 + 4096, "Information", $stext)
EndFunc

Func _winapi_showwindow($hwnd, $icmdshow = 5)
	Local $aresult = DllCall("user32.dll", "bool", "ShowWindow", "hwnd", $hwnd, "int", $icmdshow)
	If @error Then Return SetError(@error, @extended, False)
	Return $aresult[0]
EndFunc

Func _winapi_stringfromguid($pguid)
	Local $aresult = DllCall("ole32.dll", "int", "StringFromGUID2", "ptr", $pguid, "wstr", "", "int", 40)
	If @error Then Return SetError(@error, @extended, "")
	Return SetExtended($aresult[0], $aresult[2])
EndFunc

Func _winapi_sublangid($lgid)
	Return BitShift($lgid, 10)
EndFunc

Func _winapi_systemparametersinfo($iaction, $iparam = 0, $vparam = 0, $iwinini = 0)
	Local $aresult = DllCall("user32.dll", "bool", "SystemParametersInfoW", "uint", $iaction, "uint", $iparam, "ptr", $vparam, "uint", $iwinini)
	If @error Then Return SetError(@error, @extended, False)
	Return $aresult[0]
EndFunc

Func _winapi_twipsperpixelx()
	Local $lngdc, $twipsperpixelx
	$lngdc = _winapi_getdc(0)
	$twipsperpixelx = 1440 / _winapi_getdevicecaps($lngdc, $__winapiconstant_logpixelsx)
	_winapi_releasedc(0, $lngdc)
	Return $twipsperpixelx
EndFunc

Func _winapi_twipsperpixely()
	Local $lngdc, $twipsperpixely
	$lngdc = _winapi_getdc(0)
	$twipsperpixely = 1440 / _winapi_getdevicecaps($lngdc, $__winapiconstant_logpixelsy)
	_winapi_releasedc(0, $lngdc)
	Return $twipsperpixely
EndFunc

Func _winapi_unhookwindowshookex($hhk)
	Local $aresult = DllCall("user32.dll", "bool", "UnhookWindowsHookEx", "handle", $hhk)
	If @error Then Return SetError(@error, @extended, False)
	Return $aresult[0]
EndFunc

Func _winapi_updatelayeredwindow($hwnd, $hdcdest, $pptdest, $psize, $hdcsrce, $pptsrce, $irgb, $pblend, $iflags)
	Local $aresult = DllCall("user32.dll", "bool", "UpdateLayeredWindow", "hwnd", $hwnd, "handle", $hdcdest, "ptr", $pptdest, "ptr", $psize, "handle", $hdcsrce, "ptr", $pptsrce, "dword", $irgb, "ptr", $pblend, "dword", $iflags)
	If @error Then Return SetError(@error, @extended, False)
	Return $aresult[0]
EndFunc

Func _winapi_updatewindow($hwnd)
	Local $aresult = DllCall("user32.dll", "bool", "UpdateWindow", "hwnd", $hwnd)
	If @error Then Return SetError(@error, @extended, False)
	Return $aresult[0]
EndFunc

Func _winapi_waitforinputidle($hprocess, $itimeout = -1)
	Local $aresult = DllCall("user32.dll", "dword", "WaitForInputIdle", "handle", $hprocess, "dword", $itimeout)
	If @error Then Return SetError(@error, @extended, False)
	Return $aresult[0]
EndFunc

Func _winapi_waitformultipleobjects($icount, $phandles, $fwaitall = False, $itimeout = -1)
	Local $aresult = DllCall("kernel32.dll", "INT", "WaitForMultipleObjects", "dword", $icount, "ptr", $phandles, "bool", $fwaitall, "dword", $itimeout)
	If @error Then Return SetError(@error, @extended, -1)
	Return $aresult[0]
EndFunc

Func _winapi_waitforsingleobject($hhandle, $itimeout = -1)
	Local $aresult = DllCall("kernel32.dll", "INT", "WaitForSingleObject", "handle", $hhandle, "dword", $itimeout)
	If @error Then Return SetError(@error, @extended, -1)
	Return $aresult[0]
EndFunc

Func _winapi_widechartomultibyte($punicode, $icodepage = 0, $bretstring = True)
	Local $sunicodetype = "ptr"
	If IsDllStruct($punicode) Then
		$punicode = DllStructGetPtr($punicode)
	Else
		If NOT IsPtr($punicode) Then $sunicodetype = "wstr"
	EndIf
	Local $aresult = DllCall("kernel32.dll", "int", "WideCharToMultiByte", "uint", $icodepage, "dword", 0, $sunicodetype, $punicode, "int", -1, "ptr", 0, "int", 0, "ptr", 0, "ptr", 0)
	If @error Then Return SetError(@error, @extended, "")
	Local $tmultibyte = DllStructCreate("char[" & $aresult[0] & "]")
	Local $pmultibyte = DllStructGetPtr($tmultibyte)
	$aresult = DllCall("kernel32.dll", "int", "WideCharToMultiByte", "uint", $icodepage, "dword", 0, $sunicodetype, $punicode, "int", -1, "ptr", $pmultibyte, "int", $aresult[0], "ptr", 0, "ptr", 0)
	If @error Then Return SetError(@error, @extended, "")
	If $bretstring Then Return DllStructGetData($tmultibyte, 1)
	Return $tmultibyte
EndFunc

Func _winapi_windowfrompoint(ByRef $tpoint)
	Local $tpointcast = DllStructCreate("int64", DllStructGetPtr($tpoint))
	Local $aresult = DllCall("user32.dll", "hwnd", "WindowFromPoint", "int64", DllStructGetData($tpointcast, 1))
	If @error Then Return SetError(@error, @extended, 0)
	Return $aresult[0]
EndFunc

Func _winapi_writeconsole($hconsole, $stext)
	Local $aresult = DllCall("kernel32.dll", "bool", "WriteConsoleW", "handle", $hconsole, "wstr", $stext, "dword", StringLen($stext), "dword*", 0, "ptr", 0)
	If @error Then Return SetError(@error, @extended, False)
	Return $aresult[0]
EndFunc

Func _winapi_writefile($hfile, $pbuffer, $itowrite, ByRef $iwritten, $poverlapped = 0)
	Local $aresult = DllCall("kernel32.dll", "bool", "WriteFile", "handle", $hfile, "ptr", $pbuffer, "dword", $itowrite, "dword*", 0, "ptr", $poverlapped)
	If @error Then Return SetError(@error, @extended, False)
	$iwritten = $aresult[4]
	Return $aresult[0]
EndFunc

Func _winapi_writeprocessmemory($hprocess, $pbaseaddress, $pbuffer, $isize, ByRef $iwritten, $sbuffer = "ptr")
	Local $aresult = DllCall("kernel32.dll", "bool", "WriteProcessMemory", "handle", $hprocess, "ptr", $pbaseaddress, $sbuffer, $pbuffer, "ulong_ptr", $isize, "ulong_ptr*", 0)
	If @error Then Return SetError(@error, @extended, False)
	$iwritten = $aresult[5]
	Return $aresult[0]
EndFunc

Global Const $_udf_globalids_offset = 2
Global Const $_udf_globalid_max_win = 16
Global Const $_udf_startid = 10000
Global Const $_udf_globalid_max_ids = 55535
Global Const $__udfguiconstant_ws_visible = 268435456
Global Const $__udfguiconstant_ws_child = 1073741824
Global $_udf_globalids_used[$_udf_globalid_max_win][$_udf_globalid_max_ids + $_udf_globalids_offset + 1]

Func __udf_getnextglobalid($hwnd)
	Local $nctrlid, $iusedindex = -1, $fallused = True
	If NOT WinExists($hwnd) Then Return SetError(-1, -1, 0)
	For $iindex = 0 To $_udf_globalid_max_win - 1
		If $_udf_globalids_used[$iindex][0] <> 0 Then
			If NOT WinExists($_udf_globalids_used[$iindex][0]) Then
				For $x = 0 To UBound($_udf_globalids_used, 2) - 1
					$_udf_globalids_used[$iindex][$x] = 0
				Next
				$_udf_globalids_used[$iindex][1] = $_udf_startid
				$fallused = False
			EndIf
		EndIf
	Next
	For $iindex = 0 To $_udf_globalid_max_win - 1
		If $_udf_globalids_used[$iindex][0] = $hwnd Then
			$iusedindex = $iindex
			ExitLoop 
		EndIf
	Next
	If $iusedindex = -1 Then
		For $iindex = 0 To $_udf_globalid_max_win - 1
			If $_udf_globalids_used[$iindex][0] = 0 Then
				$_udf_globalids_used[$iindex][0] = $hwnd
				$_udf_globalids_used[$iindex][1] = $_udf_startid
				$fallused = False
				$iusedindex = $iindex
				ExitLoop 
			EndIf
		Next
	EndIf
	If $iusedindex = -1 AND $fallused Then Return SetError(16, 0, 0)
	If $_udf_globalids_used[$iusedindex][1] = $_udf_startid + $_udf_globalid_max_ids Then
		For $iidindex = $_udf_globalids_offset To UBound($_udf_globalids_used, 2) - 1
			If $_udf_globalids_used[$iusedindex][$iidindex] = 0 Then
				$nctrlid = ($iidindex - $_udf_globalids_offset) + 10000
				$_udf_globalids_used[$iusedindex][$iidindex] = $nctrlid
				Return $nctrlid
			EndIf
		Next
		Return SetError(-1, $_udf_globalid_max_ids, 0)
	EndIf
	$nctrlid = $_udf_globalids_used[$iusedindex][1]
	$_udf_globalids_used[$iusedindex][1] += 1
	$_udf_globalids_used[$iusedindex][($nctrlid - 10000) + $_udf_globalids_offset] = $nctrlid
	Return $nctrlid
EndFunc

Func __udf_freeglobalid($hwnd, $iglobalid)
	If $iglobalid - $_udf_startid < 0 OR $iglobalid - $_udf_startid > $_udf_globalid_max_ids Then Return SetError(-1, 0, False)
	For $iindex = 0 To $_udf_globalid_max_win - 1
		If $_udf_globalids_used[$iindex][0] = $hwnd Then
			For $x = $_udf_globalids_offset To UBound($_udf_globalids_used, 2) - 1
				If $_udf_globalids_used[$iindex][$x] = $iglobalid Then
					$_udf_globalids_used[$iindex][$x] = 0
					Return True
				EndIf
			Next
			Return SetError(-3, 0, False)
		EndIf
	Next
	Return SetError(-2, 0, False)
EndFunc

Func __udf_debugprint($stext, $iline = @ScriptLineNumber, $err = @error, $ext = @extended)
	ConsoleWrite("!===========================================================" & @CRLF & "+======================================================" & @CRLF & "-->Line(" & StringFormat("%04d", $iline) & "):" & @TAB & $stext & @CRLF & "+======================================================" & @CRLF)
	Return SetError($err, $ext, 1)
EndFunc

Func __udf_validateclassname($hwnd, $sclassnames)
	__udf_debugprint("This is for debugging only, set the debug variable to false before submitting")
	If _winapi_isclassname($hwnd, $sclassnames) Then Return True
	Local $sseparator = Opt("GUIDataSeparatorChar")
	$sclassnames = StringReplace($sclassnames, $sseparator, ",")
	__udf_debugprint("Invalid Class Type(s):" & @LF & @TAB & "Expecting Type(s): " & $sclassnames & @LF & @TAB & "Received Type : " & _winapi_getclassname($hwnd))
	Exit 
EndFunc

Global $_lb_ghlastwnd
Global $debug_lb = False
Global Const $__listboxconstant_classname = "ListBox"
Global Const $__listboxconstant_classnames = $__listboxconstant_classname & "|TListbox"
Global Const $__listboxconstant_ws_tabstop = 65536
Global Const $__listboxconstant_default_gui_font = 17
Global Const $__listboxconstant_wm_setredraw = 11
Global Const $__listboxconstant_wm_getfont = 49

Func _guictrllistbox_addfile($hwnd, $sfile)
	If $debug_lb Then __udf_validateclassname($hwnd, $__listboxconstant_classnames)
	If IsHWnd($hwnd) Then
		Return _sendmessage($hwnd, $lb_addfile, 0, $sfile, 0, "wparam", "wstr")
	Else
		Return GUICtrlSendMsg($hwnd, $lb_addfile, 0, $sfile)
	EndIf
EndFunc

Func _guictrllistbox_addstring($hwnd, $stext)
	If $debug_lb Then __udf_validateclassname($hwnd, $__listboxconstant_classnames)
	If IsHWnd($hwnd) Then
		Return _sendmessage($hwnd, $lb_addstring, 0, $stext, 0, "wparam", "wstr")
	Else
		Return GUICtrlSendMsg($hwnd, $lb_addstring, 0, $stext)
	EndIf
EndFunc

Func _guictrllistbox_beginupdate($hwnd)
	If $debug_lb Then __udf_validateclassname($hwnd, $__listboxconstant_classnames)
	If NOT IsHWnd($hwnd) Then $hwnd = GUICtrlGetHandle($hwnd)
	Return _sendmessage($hwnd, $__listboxconstant_wm_setredraw) = 0
EndFunc

Func _guictrllistbox_clickitem($hwnd, $iindex, $sbutton = "left", $fmove = False, $iclicks = 1, $ispeed = 0)
	If $debug_lb Then __udf_validateclassname($hwnd, $__listboxconstant_classnames)
	If NOT IsHWnd($hwnd) Then $hwnd = GUICtrlGetHandle($hwnd)
	Local $trect = _guictrllistbox_getitemrectex($hwnd, $iindex)
	Local $tpoint = _winapi_pointfromrect($trect)
	$tpoint = _winapi_clienttoscreen($hwnd, $tpoint)
	Local $ix, $iy
	_winapi_getxyfrompoint($tpoint, $ix, $iy)
	Local $imode = Opt("MouseCoordMode", 1)
	If NOT $fmove Then
		Local $apos = MouseGetPos()
		_winapi_showcursor(False)
		MouseClick($sbutton, $ix, $iy, $iclicks, $ispeed)
		MouseMove($apos[0], $apos[1], 0)
		_winapi_showcursor(True)
	Else
		MouseClick($sbutton, $ix, $iy, $iclicks, $ispeed)
	EndIf
	Opt("MouseCoordMode", $imode)
EndFunc

Func _guictrllistbox_create($hwnd, $stext, $ix, $iy, $iwidth = 100, $iheight = 200, $istyle = 11534338, $iexstyle = 512)
	If NOT IsHWnd($hwnd) Then
		Return SetError(1, 0, 0)
	EndIf
	If NOT IsString($stext) Then
		Return SetError(2, 0, 0)
	EndIf
	If $iwidth = -1 Then $iwidth = 100
	If $iheight = -1 Then $iheight = 200
	Local Const $ws_vscroll = 2097152, $ws_hscroll = 1048576, $ws_border = 8388608
	If $istyle = -1 Then $istyle = BitOR($ws_border, $ws_vscroll, $ws_hscroll, $lbs_sort)
	If $iexstyle = -1 Then $iexstyle = 512
	$istyle = BitOR($istyle, $__udfguiconstant_ws_visible, $__listboxconstant_ws_tabstop, $__udfguiconstant_ws_child, $lbs_notify)
	Local $nctrlid = __udf_getnextglobalid($hwnd)
	If @error Then Return SetError(@error, @extended, 0)
	Local $hlist = _winapi_createwindowex($iexstyle, $__listboxconstant_classname, "", $istyle, $ix, $iy, $iwidth, $iheight, $hwnd, $nctrlid)
	_winapi_setfont($hlist, _winapi_getstockobject($__listboxconstant_default_gui_font))
	If StringLen($stext) Then _guictrllistbox_addstring($hlist, $stext)
	Return $hlist
EndFunc

Func _guictrllistbox_deletestring($hwnd, $iindex)
	If $debug_lb Then __udf_validateclassname($hwnd, $__listboxconstant_classnames)
	If IsHWnd($hwnd) Then
		Return _sendmessage($hwnd, $lb_deletestring, $iindex)
	Else
		Return GUICtrlSendMsg($hwnd, $lb_deletestring, $iindex, 0)
	EndIf
EndFunc

Func _guictrllistbox_destroy(ByRef $hwnd)
	If $debug_lb Then __udf_validateclassname($hwnd, $__listboxconstant_classnames)
	Local $destroyed = 0
	If IsHWnd($hwnd) Then
		If _winapi_inprocess($hwnd, $_lb_ghlastwnd) Then
			Local $nctrlid = _winapi_getdlgctrlid($hwnd)
			Local $hparent = _winapi_getparent($hwnd)
			$destroyed = _winapi_destroywindow($hwnd)
			Local $iret = __udf_freeglobalid($hparent, $nctrlid)
			If NOT $iret Then
			EndIf
		Else
			Return SetError(1, 1, False)
		EndIf
	Else
		$destroyed = GUICtrlDelete($hwnd)
	EndIf
	If $destroyed Then $hwnd = 0
	Return $destroyed <> 0
EndFunc

Func _guictrllistbox_dir($hwnd, $sfile, $iattributes = 0, $fbrackets = True)
	If $debug_lb Then __udf_validateclassname($hwnd, $__listboxconstant_classnames)
	If BitAND($iattributes, $ddl_drives) = $ddl_drives AND NOT $fbrackets Then
		Local $stext
		Local $gui_no_brackets = GUICreate("no brackets")
		Local $list_no_brackets = GUICtrlCreateList("", 240, 40, 120, 120)
		Local $v_ret = GUICtrlSendMsg($list_no_brackets, $lb_dir, $iattributes, $sfile)
		For $i = 0 To _guictrllistbox_getcount($list_no_brackets) - 1
			$stext = _guictrllistbox_gettext($list_no_brackets, $i)
			$stext = StringReplace(StringReplace(StringReplace($stext, "[", ""), "]", ":"), "-", "")
			_guictrllistbox_insertstring($hwnd, $stext)
		Next
		GUIDelete($gui_no_brackets)
		Return $v_ret
	Else
		If IsHWnd($hwnd) Then
			Return _sendmessage($hwnd, $lb_dir, $iattributes, $sfile, 0, "wparam", "wstr")
		Else
			Return GUICtrlSendMsg($hwnd, $lb_dir, $iattributes, $sfile)
		EndIf
	EndIf
EndFunc

Func _guictrllistbox_endupdate($hwnd)
	If $debug_lb Then __udf_validateclassname($hwnd, $__listboxconstant_classnames)
	If NOT IsHWnd($hwnd) Then $hwnd = GUICtrlGetHandle($hwnd)
	Return _sendmessage($hwnd, $__listboxconstant_wm_setredraw, 1, 0) = 0
EndFunc

Func _guictrllistbox_findstring($hwnd, $stext, $fexact = False)
	If $debug_lb Then __udf_validateclassname($hwnd, $__listboxconstant_classnames)
	If IsHWnd($hwnd) Then
		If ($fexact) Then
			Return _sendmessage($hwnd, $lb_findstringexact, -1, $stext, 0, "wparam", "wstr")
		Else
			Return _sendmessage($hwnd, $lb_findstring, -1, $stext, 0, "wparam", "wstr")
		EndIf
	Else
		If ($fexact) Then
			Return GUICtrlSendMsg($hwnd, $lb_findstringexact, -1, $stext)
		Else
			Return GUICtrlSendMsg($hwnd, $lb_findstring, -1, $stext)
		EndIf
	EndIf
EndFunc

Func _guictrllistbox_findintext($hwnd, $stext, $istart = -1, $fwrapok = True)
	Local $slist
	Local $icount = _guictrllistbox_getcount($hwnd)
	For $ii = $istart + 1 To $icount - 1
		$slist = _guictrllistbox_gettext($hwnd, $ii)
		If StringInStr($slist, $stext) Then Return $ii
	Next
	If ($istart = -1) OR NOT $fwrapok Then Return  - 1
	For $ii = 0 To $istart - 1
		$slist = _guictrllistbox_gettext($hwnd, $ii)
		If StringInStr($slist, $stext) Then Return $ii
	Next
	Return  - 1
EndFunc

Func _guictrllistbox_getanchorindex($hwnd)
	If $debug_lb Then __udf_validateclassname($hwnd, $__listboxconstant_classnames)
	If IsHWnd($hwnd) Then
		Return _sendmessage($hwnd, $lb_getanchorindex)
	Else
		Return GUICtrlSendMsg($hwnd, $lb_getanchorindex, 0, 0)
	EndIf
EndFunc

Func _guictrllistbox_getcaretindex($hwnd)
	If $debug_lb Then __udf_validateclassname($hwnd, $__listboxconstant_classnames)
	If IsHWnd($hwnd) Then
		Return _sendmessage($hwnd, $lb_getcaretindex)
	Else
		Return GUICtrlSendMsg($hwnd, $lb_getcaretindex, 0, 0)
	EndIf
EndFunc

Func _guictrllistbox_getcount($hwnd)
	If $debug_lb Then __udf_validateclassname($hwnd, $__listboxconstant_classnames)
	If IsHWnd($hwnd) Then
		Return _sendmessage($hwnd, $lb_getcount)
	Else
		Return GUICtrlSendMsg($hwnd, $lb_getcount, 0, 0)
	EndIf
EndFunc

Func _guictrllistbox_getcursel($hwnd)
	If $debug_lb Then __udf_validateclassname($hwnd, $__listboxconstant_classnames)
	If IsHWnd($hwnd) Then
		Return _sendmessage($hwnd, $lb_getcursel)
	Else
		Return GUICtrlSendMsg($hwnd, $lb_getcursel, 0, 0)
	EndIf
EndFunc

Func _guictrllistbox_gethorizontalextent($hwnd)
	If $debug_lb Then __udf_validateclassname($hwnd, $__listboxconstant_classnames)
	If IsHWnd($hwnd) Then
		Return _sendmessage($hwnd, $lb_gethorizontalextent)
	Else
		Return GUICtrlSendMsg($hwnd, $lb_gethorizontalextent, 0, 0)
	EndIf
EndFunc

Func _guictrllistbox_getitemdata($hwnd, $iindex)
	If $debug_lb Then __udf_validateclassname($hwnd, $__listboxconstant_classnames)
	If IsHWnd($hwnd) Then
		Return _sendmessage($hwnd, $lb_getitemdata, $iindex)
	Else
		Return GUICtrlSendMsg($hwnd, $lb_getitemdata, $iindex, 0)
	EndIf
EndFunc

Func _guictrllistbox_getitemheight($hwnd)
	If $debug_lb Then __udf_validateclassname($hwnd, $__listboxconstant_classnames)
	If IsHWnd($hwnd) Then
		Return _sendmessage($hwnd, $lb_getitemheight)
	Else
		Return GUICtrlSendMsg($hwnd, $lb_getitemheight, 0, 0)
	EndIf
EndFunc

Func _guictrllistbox_getitemrect($hwnd, $iindex)
	Local $arect[4]
	Local $trect = _guictrllistbox_getitemrectex($hwnd, $iindex)
	$arect[0] = DllStructGetData($trect, "Left")
	$arect[1] = DllStructGetData($trect, "Top")
	$arect[2] = DllStructGetData($trect, "Right")
	$arect[3] = DllStructGetData($trect, "Bottom")
	Return $arect
EndFunc

Func _guictrllistbox_getitemrectex($hwnd, $iindex)
	If $debug_lb Then __udf_validateclassname($hwnd, $__listboxconstant_classnames)
	Local $trect = DllStructCreate($tagrect)
	If IsHWnd($hwnd) Then
		_sendmessage($hwnd, $lb_getitemrect, $iindex, DllStructGetPtr($trect), 0, "wparam", "ptr")
	Else
		GUICtrlSendMsg($hwnd, $lb_getitemrect, $iindex, DllStructGetPtr($trect))
	EndIf
	Return $trect
EndFunc

Func _guictrllistbox_getlistboxinfo($hwnd)
	If $debug_lb Then __udf_validateclassname($hwnd, $__listboxconstant_classnames)
	If IsHWnd($hwnd) Then
		Return _sendmessage($hwnd, $lb_getlistboxinfo)
	Else
		Return GUICtrlSendMsg($hwnd, $lb_getlistboxinfo, 0, 0)
	EndIf
EndFunc

Func _guictrllistbox_getlocale($hwnd)
	If $debug_lb Then __udf_validateclassname($hwnd, $__listboxconstant_classnames)
	If IsHWnd($hwnd) Then
		Return _sendmessage($hwnd, $lb_getlocale)
	Else
		Return GUICtrlSendMsg($hwnd, $lb_getlocale, 0, 0)
	EndIf
EndFunc

Func _guictrllistbox_getlocalecountry($hwnd)
	Return _winapi_hiword(_guictrllistbox_getlocale($hwnd))
EndFunc

Func _guictrllistbox_getlocalelang($hwnd)
	Return _winapi_loword(_guictrllistbox_getlocale($hwnd))
EndFunc

Func _guictrllistbox_getlocaleprimlang($hwnd)
	Return _winapi_primarylangid(_guictrllistbox_getlocalelang($hwnd))
EndFunc

Func _guictrllistbox_getlocalesublang($hwnd)
	Return _winapi_sublangid(_guictrllistbox_getlocalelang($hwnd))
EndFunc

Func _guictrllistbox_getsel($hwnd, $iindex)
	If $debug_lb Then __udf_validateclassname($hwnd, $__listboxconstant_classnames)
	If IsHWnd($hwnd) Then
		Return _sendmessage($hwnd, $lb_getsel, $iindex) <> 0
	Else
		Return GUICtrlSendMsg($hwnd, $lb_getsel, $iindex, 0) <> 0
	EndIf
EndFunc

Func _guictrllistbox_getselcount($hwnd)
	If $debug_lb Then __udf_validateclassname($hwnd, $__listboxconstant_classnames)
	If IsHWnd($hwnd) Then
		Return _sendmessage($hwnd, $lb_getselcount)
	Else
		Return GUICtrlSendMsg($hwnd, $lb_getselcount, 0, 0)
	EndIf
EndFunc

Func _guictrllistbox_getselitems($hwnd)
	If $debug_lb Then __udf_validateclassname($hwnd, $__listboxconstant_classnames)
	Local $aarray[1] = [0]
	Local $icount = _guictrllistbox_getselcount($hwnd)
	If $icount > 0 Then
		ReDim $aarray[$icount + 1]
		Local $tarray = DllStructCreate("int[" & $icount & "]")
		If IsHWnd($hwnd) Then
			_sendmessage($hwnd, $lb_getselitems, $icount, DllStructGetPtr($tarray), 0, "wparam", "ptr")
		Else
			GUICtrlSendMsg($hwnd, $lb_getselitems, $icount, DllStructGetPtr($tarray))
		EndIf
		$aarray[0] = $icount
		For $ii = 1 To $icount
			$aarray[$ii] = DllStructGetData($tarray, 1, $ii)
		Next
	EndIf
	Return $aarray
EndFunc

Func _guictrllistbox_getselitemstext($hwnd)
	If $debug_lb Then __udf_validateclassname($hwnd, $__listboxconstant_classnames)
	Local $atext[1] = [0], $icount = _guictrllistbox_getselcount($hwnd)
	If $icount > 0 Then
		Local $aindices = _guictrllistbox_getselitems($hwnd)
		ReDim $atext[UBound($aindices)]
		$atext[0] = $aindices[0]
		For $i = 1 To $aindices[0]
			$atext[$i] = _guictrllistbox_gettext($hwnd, $aindices[$i])
		Next
	EndIf
	Return $atext
EndFunc

Func _guictrllistbox_gettext($hwnd, $iindex)
	If $debug_lb Then __udf_validateclassname($hwnd, $__listboxconstant_classnames)
	Local $ttext = DllStructCreate("wchar Text[" & _guictrllistbox_gettextlen($hwnd, $iindex) + 1 & "]")
	If NOT IsHWnd($hwnd) Then $hwnd = GUICtrlGetHandle($hwnd)
	_sendmessage($hwnd, $lb_gettext, $iindex, DllStructGetPtr($ttext), 0, "wparam", "ptr")
	Return DllStructGetData($ttext, "Text")
EndFunc

Func _guictrllistbox_gettextlen($hwnd, $iindex)
	If $debug_lb Then __udf_validateclassname($hwnd, $__listboxconstant_classnames)
	If IsHWnd($hwnd) Then
		Return _sendmessage($hwnd, $lb_gettextlen, $iindex)
	Else
		Return GUICtrlSendMsg($hwnd, $lb_gettextlen, $iindex, 0)
	EndIf
EndFunc

Func _guictrllistbox_gettopindex($hwnd)
	If $debug_lb Then __udf_validateclassname($hwnd, $__listboxconstant_classnames)
	If IsHWnd($hwnd) Then
		Return _sendmessage($hwnd, $lb_gettopindex)
	Else
		Return GUICtrlSendMsg($hwnd, $lb_gettopindex, 0, 0)
	EndIf
EndFunc

Func _guictrllistbox_initstorage($hwnd, $iitems, $ibytes)
	If $debug_lb Then __udf_validateclassname($hwnd, $__listboxconstant_classnames)
	If IsHWnd($hwnd) Then
		Return _sendmessage($hwnd, $lb_initstorage, $iitems, $ibytes)
	Else
		Return GUICtrlSendMsg($hwnd, $lb_initstorage, $iitems, $ibytes)
	EndIf
EndFunc

Func _guictrllistbox_insertstring($hwnd, $stext, $iindex = -1)
	If $debug_lb Then __udf_validateclassname($hwnd, $__listboxconstant_classnames)
	If IsHWnd($hwnd) Then
		Return _sendmessage($hwnd, $lb_insertstring, $iindex, $stext, 0, "wparam", "wstr")
	Else
		Return GUICtrlSendMsg($hwnd, $lb_insertstring, $iindex, $stext)
	EndIf
EndFunc

Func _guictrllistbox_itemfrompoint($hwnd, $ix, $iy)
	If $debug_lb Then __udf_validateclassname($hwnd, $__listboxconstant_classnames)
	Local $iret
	If IsHWnd($hwnd) Then
		$iret = _sendmessage($hwnd, $lb_itemfrompoint, 0, _winapi_makelong($ix, $iy))
	Else
		$iret = GUICtrlSendMsg($hwnd, $lb_itemfrompoint, 0, _winapi_makelong($ix, $iy))
	EndIf
	If _winapi_hiword($iret) <> 0 Then $iret = -1
	Return $iret
EndFunc

Func _guictrllistbox_replacestring($hwnd, $iindex, $stext)
	If $debug_lb Then __udf_validateclassname($hwnd, $__listboxconstant_classnames)
	If (_guictrllistbox_deletestring($hwnd, $iindex) == $lb_err) Then Return SetError($lb_err, $lb_err, False)
	If (_guictrllistbox_insertstring($hwnd, $stext, $iindex) == $lb_err) Then Return SetError($lb_err, $lb_err, False)
	Return True
EndFunc

Func _guictrllistbox_resetcontent($hwnd)
	If $debug_lb Then __udf_validateclassname($hwnd, $__listboxconstant_classnames)
	If IsHWnd($hwnd) Then
		_sendmessage($hwnd, $lb_resetcontent)
	Else
		GUICtrlSendMsg($hwnd, $lb_resetcontent, 0, 0)
	EndIf
EndFunc

Func _guictrllistbox_selectstring($hwnd, $stext, $iindex = -1)
	If $debug_lb Then __udf_validateclassname($hwnd, $__listboxconstant_classnames)
	If IsHWnd($hwnd) Then
		Return _sendmessage($hwnd, $lb_selectstring, $iindex, $stext, 0, "wparam", "wstr")
	Else
		Return GUICtrlSendMsg($hwnd, $lb_selectstring, $iindex, $stext)
	EndIf
EndFunc

Func _guictrllistbox_selitemrange($hwnd, $ifirst, $ilast, $fselect = True)
	If $debug_lb Then __udf_validateclassname($hwnd, $__listboxconstant_classnames)
	If IsHWnd($hwnd) Then
		Return _sendmessage($hwnd, $lb_selitemrange, $fselect, _winapi_makelong($ifirst, $ilast)) = 0
	Else
		Return GUICtrlSendMsg($hwnd, $lb_selitemrange, $fselect, _winapi_makelong($ifirst, $ilast)) = 0
	EndIf
EndFunc

Func _guictrllistbox_selitemrangeex($hwnd, $ifirst, $ilast)
	If $debug_lb Then __udf_validateclassname($hwnd, $__listboxconstant_classnames)
	If IsHWnd($hwnd) Then
		Return _sendmessage($hwnd, $lb_selitemrangeex, $ifirst, $ilast) = 0
	Else
		Return GUICtrlSendMsg($hwnd, $lb_selitemrangeex, $ifirst, $ilast) = 0
	EndIf
EndFunc

Func _guictrllistbox_setanchorindex($hwnd, $iindex)
	If $debug_lb Then __udf_validateclassname($hwnd, $__listboxconstant_classnames)
	If IsHWnd($hwnd) Then
		Return _sendmessage($hwnd, $lb_setanchorindex, $iindex) = 0
	Else
		Return GUICtrlSendMsg($hwnd, $lb_setanchorindex, $iindex, 0) = 0
	EndIf
EndFunc

Func _guictrllistbox_setcaretindex($hwnd, $iindex, $fpartial = False)
	If $debug_lb Then __udf_validateclassname($hwnd, $__listboxconstant_classnames)
	If IsHWnd($hwnd) Then
		Return _sendmessage($hwnd, $lb_setcaretindex, $iindex, $fpartial) = 0
	Else
		Return GUICtrlSendMsg($hwnd, $lb_setcaretindex, $iindex, $fpartial) = 0
	EndIf
EndFunc

Func _guictrllistbox_setcolumnwidth($hwnd, $iwidth)
	If $debug_lb Then __udf_validateclassname($hwnd, $__listboxconstant_classnames)
	If IsHWnd($hwnd) Then
		_sendmessage($hwnd, $lb_setcolumnwidth, $iwidth)
	Else
		GUICtrlSendMsg($hwnd, $lb_setcolumnwidth, $iwidth, 0)
	EndIf
EndFunc

Func _guictrllistbox_setcursel($hwnd, $iindex)
	If $debug_lb Then __udf_validateclassname($hwnd, $__listboxconstant_classnames)
	If IsHWnd($hwnd) Then
		Return _sendmessage($hwnd, $lb_setcursel, $iindex)
	Else
		Return GUICtrlSendMsg($hwnd, $lb_setcursel, $iindex, 0)
	EndIf
EndFunc

Func _guictrllistbox_sethorizontalextent($hwnd, $iwidth)
	If $debug_lb Then __udf_validateclassname($hwnd, $__listboxconstant_classnames)
	If IsHWnd($hwnd) Then
		_sendmessage($hwnd, $lb_sethorizontalextent, $iwidth)
	Else
		GUICtrlSendMsg($hwnd, $lb_sethorizontalextent, $iwidth, 0)
	EndIf
EndFunc

Func _guictrllistbox_setitemdata($hwnd, $iindex, $ivalue)
	If $debug_lb Then __udf_validateclassname($hwnd, $__listboxconstant_classnames)
	If IsHWnd($hwnd) Then
		Return _sendmessage($hwnd, $lb_setitemdata, $iindex, $ivalue) <> -1
	Else
		Return GUICtrlSendMsg($hwnd, $lb_setitemdata, $iindex, $ivalue) <> -1
	EndIf
EndFunc

Func _guictrllistbox_setitemheight($hwnd, $iheight, $iindex = 0)
	If $debug_lb Then __udf_validateclassname($hwnd, $__listboxconstant_classnames)
	Local $iret
	If IsHWnd($hwnd) Then
		$iret = _sendmessage($hwnd, $lb_setitemheight, $iindex, $iheight)
		_winapi_invalidaterect($hwnd)
	Else
		$iret = GUICtrlSendMsg($hwnd, $lb_setitemheight, $iindex, $iheight)
		_winapi_invalidaterect(GUICtrlGetHandle($hwnd))
	EndIf
	Return $iret <> -1
EndFunc

Func _guictrllistbox_setlocale($hwnd, $ilocal)
	If $debug_lb Then __udf_validateclassname($hwnd, $__listboxconstant_classnames)
	If IsHWnd($hwnd) Then
		Return _sendmessage($hwnd, $lb_setlocale, $ilocal)
	Else
		Return GUICtrlSendMsg($hwnd, $lb_setlocale, $ilocal, 0)
	EndIf
EndFunc

Func _guictrllistbox_setsel($hwnd, $iindex = -1, $fselect = -1)
	If $debug_lb Then __udf_validateclassname($hwnd, $__listboxconstant_classnames)
	Local $i_ret = True
	If IsHWnd($hwnd) Then
		If $iindex == -1 Then
			For $iindex = 0 To _guictrllistbox_getcount($hwnd) - 1
				$i_ret = _guictrllistbox_getsel($hwnd, $iindex)
				If ($i_ret == $lb_err) Then Return SetError($lb_err, $lb_err, False)
				If ($i_ret > 0) Then
					$i_ret = _sendmessage($hwnd, $lb_setsel, False, $iindex) <> -1
				Else
					$i_ret = _sendmessage($hwnd, $lb_setsel, True, $iindex) <> -1
				EndIf
				If ($i_ret == False) Then Return SetError($lb_err, $lb_err, False)
			Next
		ElseIf $fselect == -1 Then
			If _guictrllistbox_getsel($hwnd, $iindex) Then
				Return _sendmessage($hwnd, $lb_setsel, False, $iindex) <> -1
			Else
				Return _sendmessage($hwnd, $lb_setsel, True, $iindex) <> -1
			EndIf
		Else
			Return _sendmessage($hwnd, $lb_setsel, $fselect, $iindex) <> -1
		EndIf
	Else
		If $iindex == -1 Then
			For $iindex = 0 To _guictrllistbox_getcount($hwnd) - 1
				$i_ret = _guictrllistbox_getsel($hwnd, $iindex)
				If ($i_ret == $lb_err) Then Return SetError($lb_err, $lb_err, False)
				If ($i_ret > 0) Then
					$i_ret = GUICtrlSendMsg($hwnd, $lb_setsel, False, $iindex) <> -1
				Else
					$i_ret = GUICtrlSendMsg($hwnd, $lb_setsel, True, $iindex) <> -1
				EndIf
				If ($i_ret == False) Then Return SetError($lb_err, $lb_err, False)
			Next
		ElseIf $fselect == -1 Then
			If _guictrllistbox_getsel($hwnd, $iindex) Then
				Return GUICtrlSendMsg($hwnd, $lb_setsel, False, $iindex) <> -1
			Else
				Return GUICtrlSendMsg($hwnd, $lb_setsel, True, $iindex) <> -1
			EndIf
		Else
			Return GUICtrlSendMsg($hwnd, $lb_setsel, $fselect, $iindex) <> -1
		EndIf
	EndIf
	Return $i_ret
EndFunc

Func _guictrllistbox_settabstops($hwnd, $atabstops)
	If $debug_lb Then __udf_validateclassname($hwnd, $__listboxconstant_classnames)
	Local $icount = $atabstops[0]
	Local $ttabstops = DllStructCreate("int[" & $icount & "]")
	For $ii = 1 To $icount
		DllStructSetData($ttabstops, 1, $atabstops[$ii], $ii)
	Next
	If IsHWnd($hwnd) Then
		Return _sendmessage($hwnd, $lb_settabstops, $icount, DllStructGetPtr($ttabstops), 0, "wparam", "ptr") = 0
	Else
		Return GUICtrlSendMsg($hwnd, $lb_settabstops, $icount, DllStructGetPtr($ttabstops)) = 0
	EndIf
EndFunc

Func _guictrllistbox_settopindex($hwnd, $iindex)
	If $debug_lb Then __udf_validateclassname($hwnd, $__listboxconstant_classnames)
	If IsHWnd($hwnd) Then
		Return _sendmessage($hwnd, $lb_settopindex, $iindex) <> -1
	Else
		Return GUICtrlSendMsg($hwnd, $lb_settopindex, $iindex, 0) <> -1
	EndIf
EndFunc

Func _guictrllistbox_sort($hwnd)
	If $debug_lb Then __udf_validateclassname($hwnd, $__listboxconstant_classnames)
	Local $bak = _guictrllistbox_gettext($hwnd, 0)
	If ($bak == -1) Then Return SetError($lb_err, $lb_err, False)
	If (_guictrllistbox_deletestring($hwnd, 0) == -1) Then Return SetError($lb_err, $lb_err, False)
	Return _guictrllistbox_addstring($hwnd, $bak) <> -1
EndFunc

Func _guictrllistbox_swapstring($hwnd, $iindexa, $iindexb)
	If $debug_lb Then __udf_validateclassname($hwnd, $__listboxconstant_classnames)
	Local $itema = _guictrllistbox_gettext($hwnd, $iindexa)
	Local $itemb = _guictrllistbox_gettext($hwnd, $iindexb)
	If (_guictrllistbox_deletestring($hwnd, $iindexa) == -1) Then Return SetError($lb_err, $lb_err, False)
	If (_guictrllistbox_insertstring($hwnd, $itemb, $iindexa) == -1) Then Return SetError($lb_err, $lb_err, False)
	If (_guictrllistbox_deletestring($hwnd, $iindexb) == -1) Then Return SetError($lb_err, $lb_err, False)
	If (_guictrllistbox_insertstring($hwnd, $itema, $iindexb) == -1) Then Return SetError($lb_err, $lb_err, False)
	Return True
EndFunc

Func _guictrllistbox_updatehscroll($hwnd)
	If $debug_lb Then __udf_validateclassname($hwnd, $__listboxconstant_classnames)
	Local $hdc, $hfont, $tsize, $stext
	Local $imax = 0
	If IsHWnd($hwnd) Then
		$hfont = _sendmessage($hwnd, $__listboxconstant_wm_getfont)
		$hdc = _winapi_getdc($hwnd)
		_winapi_selectobject($hdc, $hfont)
		For $ii = 0 To _guictrllistbox_getcount($hwnd) - 1
			$stext = _guictrllistbox_gettext($hwnd, $ii)
			$tsize = _winapi_gettextextentpoint32($hdc, $stext & "W")
			If DllStructGetData($tsize, "X") > $imax Then
				$imax = DllStructGetData($tsize, "X")
			EndIf
		Next
		_guictrllistbox_sethorizontalextent($hwnd, $imax)
		_winapi_selectobject($hdc, $hfont)
		_winapi_releasedc($hwnd, $hdc)
	Else
		$hfont = GUICtrlSendMsg($hwnd, $__listboxconstant_wm_getfont, 0, 0)
		Local $t_hwnd = GUICtrlGetHandle($hwnd)
		$hdc = _winapi_getdc($t_hwnd)
		_winapi_selectobject($hdc, $hfont)
		For $ii = 0 To _guictrllistbox_getcount($hwnd) - 1
			$stext = _guictrllistbox_gettext($hwnd, $ii)
			$tsize = _winapi_gettextextentpoint32($hdc, $stext & "W")
			If DllStructGetData($tsize, "X") > $imax Then
				$imax = DllStructGetData($tsize, "X")
			EndIf
		Next
		_guictrllistbox_sethorizontalextent($hwnd, $imax)
		_winapi_selectobject($hdc, $hfont)
		_winapi_releasedc($t_hwnd, $hdc)
	EndIf
EndFunc


;pt 4*******************************

Func _processgetname($i_pid)
	If NOT ProcessExists($i_pid) Then Return SetError(1, 0, "")
	If NOT @error Then
		Local $a_processes = ProcessList()
		For $i = 1 To $a_processes[0][0]
			If $a_processes[$i][1] = $i_pid Then Return $a_processes[$i][0]
		Next
	EndIf
	Return SetError(1, 0, "")
EndFunc

Func _processgetpriority($vprocess)
	Local $ierror, $iextended, $ireturn = -1
	Local $i_pid = ProcessExists($vprocess)
	If NOT $i_pid Then Return SetError(1, 0, -1)
	Local $hdll = DllOpen("kernel32.dll")
	Do
		Local $aprocesshandle = DllCall($hdll, "handle", "OpenProcess", "dword", $process_query_information, "bool", False, "dword", $i_pid)
		If @error Then
			$ierror = @error
			$iextended = @extended
			ExitLoop 
		EndIf
		If NOT $aprocesshandle[0] Then ExitLoop 
		Local $apriority = DllCall($hdll, "dword", "GetPriorityClass", "handle", $aprocesshandle[0])
		If @error Then
			$ierror = @error
			$iextended = @extended
		EndIf
		DllCall($hdll, "bool", "CloseHandle", "handle", $aprocesshandle[0])
		If $ierror Then ExitLoop 
		Switch $apriority[0]
			Case 64
				$ireturn = 0
			Case 16384
				$ireturn = 1
			Case 32
				$ireturn = 2
			Case 32768
				$ireturn = 3
			Case 128
				$ireturn = 4
			Case 256
				$ireturn = 5
			Case Else
				$ierror = 1
				$iextended = $apriority[0]
				$ireturn = -1
		EndSwitch
	Until True
	DllClose($hdll)
	Return SetError($ierror, $iextended, $ireturn)
EndFunc

Func _rundos($scommand)
	Local $nresult = RunWait(@ComSpec & " /C " & $scommand, "", @SW_HIDE)
	Return SetError(@error, @extended, $nresult)
EndFunc

Global $_common_kernel32dll = DllOpen("kernel32.dll")
Global $_common_user32dll = DllOpen("user32.dll")
Global $process_this_handle = Ptr(-1)
If StringRegExp(@OSVersion, "_(XP|200(0|3))") Then
	Dim $process_query_limited_info = 1024
Else
	Dim $process_query_limited_info = 4096
EndIf
Global $_pfadevicetodrivemap, $_pfbdevicetodrivemapinit = False

Func __pfclosehandle(ByRef $hhandle)
	If NOT IsPtr($hhandle) OR $hhandle = 0 Then Return SetError(1, 0, False)
	Local $aret = DllCall($_common_kernel32dll, "bool", "CloseHandle", "handle", $hhandle)
	If @error Then Return SetError(2, @error, False)
	If NOT $aret[0] Then Return SetError(3, @error, False)
	$hhandle = 0
	Return True
EndFunc

Func __pfenforcepid(ByRef $vpid)
	If IsInt($vpid) Then Return True
	$vpid = ProcessExists($vpid)
	If $vpid Then Return True
	Return SetError(1, 0, False)
EndFunc

Func __pfbuilddevicetodrivexlation()
	If $_pfbdevicetodrivemapinit Then Return True
	Local $aret, $adrivearray = DriveGetDrive("ALL")
	If @error Then Return SetError(5, @error, False)
	Dim $_pfadevicetodrivemap[$adrivearray[0]][2]
	For $i = 1 To $adrivearray[0]
		$_pfadevicetodrivemap[$i - 1][0] = StringUpper($adrivearray[$i])
		$aret = DllCall($_common_kernel32dll, "dword", "QueryDosDeviceW", "wstr", $_pfadevicetodrivemap[$i - 1][0], "wstr", 0, "dword", 65536)
		If @error Then
			$_pfadevicetodrivemap = 0
			Return SetError(2, @error, False)
		EndIf
		$_pfadevicetodrivemap[$i - 1][1] = $aret[2]
	Next
	$_pfbdevicetodrivemapinit = True
	Return True
EndFunc

Func __pfxlatedevicepathname(Const ByRef $simagefilename, $bresetdrivemap)
	If NOT IsString($simagefilename) OR $simagefilename = "" Then Return SetError(1, 0, "")
	If $bresetdrivemap Then $_pfbdevicetodrivemapinit = False
	If NOT __pfbuilddevicetodrivexlation() Then Return SetError(@error, 0, "")
	For $i2 = 1 To 2
		For $i = 0 To UBound($_pfadevicetodrivemap) - 1
			If StringInStr($simagefilename, $_pfadevicetodrivemap[$i][1]) = 1 Then Return StringReplace($simagefilename, $_pfadevicetodrivemap[$i][1], $_pfadevicetodrivemap[$i][0])
		Next
		If $bresetdrivemap Then Return SetError(1, 0, "")
		$_pfbdevicetodrivemapinit = False
		If NOT __pfbuilddevicetodrivexlation() Then Return SetError(@error, 0, "")
		$bresetdrivemap = 1
	Next
	Return SetError(1, 0, "")
EndFunc

Func _processopen($vprocessid, $iaccess, $binherithandle = False)
	Local $aret
	If $vprocessid = -1 Then
		$aret = DllCall($_common_kernel32dll, "handle", "GetCurrentProcess")
		If @error Then Return SetError(2, @error, 0)
		Return $aret[0]
	ElseIf NOT __pfenforcepid($vprocessid) Then
		Return SetError(16, 0, 0)
	EndIf
	$aret = DllCall($_common_kernel32dll, "handle", "OpenProcess", "dword", $iaccess, "bool", $binherithandle, "dword", $vprocessid)
	If @error Then Return SetError(2, @error, 0)
	If NOT $aret[0] Then Return SetError(3, @error, 0)
	Return SetExtended($vprocessid, $aret[0])
EndFunc

Func _processclosehandle(ByRef $hprocess)
	If NOT __pfclosehandle($hprocess) Then Return SetError(@error, @extended, False)
	Return True
EndFunc

Func _processgetpid($hprocess)
	If NOT IsPtr($hprocess) Then Return SetError(1, 0, 0)
	Local $aret = DllCall($_common_kernel32dll, "dword", "GetProcessId", "handle", $hprocess)
	If @error Then Return SetError(2, @error, 0)
	If $aret[0] = 0 Then SetError(3)
	Return $aret[0]
EndFunc

Func _processgetexitcode($hprocess)
	If NOT IsPtr($hprocess) Then Return SetError(1, 0, -1)
	Local $aret = DllCall($_common_kernel32dll, "bool", "GetExitCodeProcess", "handle", $hprocess, "int*", 0)
	If @error Then Return SetError(2, @error, -1)
	If NOT $aret[0] Then Return SetError(3, 0, -1)
	Return $aret[2]
EndFunc

Func _processiswow64($hprocess)
	If NOT IsPtr($hprocess) Then Return SetError(1, 0, False)
	Local $aret = DllCall($_common_kernel32dll, "bool", "IsWow64Process", "handle", $hprocess, "bool*", 0)
	If @error Then
		If @error = 3 Then Return False
		Return SetError(2, @error, False)
	EndIf
	If NOT $aret[0] Then Return SetError(3, 0, False)
	Return $aret[2]
EndFunc

Func _processis32bit($hprocess)
	If @OSArch <> "X64" AND @OSArch <> "IA64" Then
		If NOT IsPtr($hprocess) Then SetError(1, 0)
		Return True
	EndIf
	If _processiswow64($hprocess) Then Return True
	Return SetError(@error, @extended, False)
EndFunc

Func _processis64bit($hprocess)
	If @OSArch = "X64" OR @OSArch = "IA64" Then
		If _processiswow64($hprocess) Then Return False
		Return SetError(@error, @extended, True)
	EndIf
	If NOT IsPtr($hprocess) Then SetError(1, 0)
	Return False
EndFunc

Func _processgetpriorityx($hprocess)
	If NOT IsPtr($hprocess) Then Return SetError(1, 0, -1)
	Local $aret = DllCall($_common_kernel32dll, "int", "GetPriorityClass", "handle", $hprocess)
	If @error Then Return SetError(2, @error, -1)
	If NOT $aret[0] Then Return SetError(3, 0, -1)
	Return $aret[0]
EndFunc

Func _processsetpriorityx($hprocess, $ipriority = 32)
	If NOT IsPtr($hprocess) Then Return SetError(1, 0, False)
	Local $aret = DllCall($_common_kernel32dll, "bool", "SetPriorityClass", "handle", $hprocess, "int", $ipriority)
	If @error Then Return SetError(2, @error, False)
	If NOT $aret[0] Then Return SetError(3, 0, False)
	Return True
EndFunc

Func _processgetaffinitymask($hprocess)
	If NOT IsPtr($hprocess) Then Return SetError(1, 0, 0)
	Local $aret = DllCall($_common_kernel32dll, "bool", "GetProcessAffinityMask", "handle", $hprocess, "dword_ptr*", 0, "dword_ptr*", 0)
	If @error Then Return SetError(2, @error, 0)
	If NOT $aret[0] Then Return SetError(3, 0, 0)
	Return SetExtended($aret[3], $aret[2])
EndFunc

Func _processsetaffinitymask($hprocess, $iaffinitymask)
	If NOT IsPtr($hprocess) Then Return SetError(1, 0, False)
	Local $aret = DllCall($_common_kernel32dll, "bool", "SetProcessAffinityMask", "handle", $hprocess, "dword_ptr", $iaffinitymask)
	If @error Then Return SetError(2, @error, False)
	If NOT $aret[0] Then Return SetError(3, 0, False)
	Return True
EndFunc

Func _processgettimes($hprocess, $itimetoget = -1)
	If NOT IsPtr($hprocess) OR $itimetoget > 3 Then Return SetError(1, 0, -1)
	Local $aret = DllCall($_common_kernel32dll, "bool", "GetProcessTimes", "handle", $hprocess, "uint64*", 0, "uint64*", 0, "uint64*", 0, "uint64*", 0)
	If @error Then Return SetError(2, @error, -1)
	If NOT $aret[0] Then Return SetError(3, 0, -1)
	If $itimetoget < 0 Then
		Dim $atimes[4] = [$aret[2], $aret[3], $aret[4], $aret[5]]
		Return $atimes
	EndIf
	Return $aret[$itimetoget + 2]
EndFunc

Func _processgetsessionid($vprocessid)
	If NOT __pfenforcepid($vprocessid) Then Return SetError(1, 0, -1)
	Local $aret = DllCall($_common_kernel32dll, "bool", "ProcessIdToSessionId", "dword", $vprocessid, "dword*", 0)
	If @error Then Return SetError(2, @error, -1)
	If NOT $aret[0] Then Return SetError(3, 0, -1)
	Return $aret[2]
EndFunc

Func _processgetowner($hprocess, $vadvapi32dll = "advapi32.dll")
	If NOT IsPtr($hprocess) OR $vadvapi32dll < 0 Then Return SetError(1, 0, "")
	Local $aownersecinfo, $agroupsecinfo, $sowner = ""
	Local $aret = DllCall($vadvapi32dll, "dword", "GetSecurityInfo", "handle", $hprocess, "int", 6, "dword", 3, "ptr*", 0, "ptr*", 0, "ptr*", 0, "ptr*", 0, "ptr*", 0)
	If @error Then Return SetError(2, @error, "")
	If $aret[0] Then Return SetError(3, $aret[0], "")
	$aownersecinfo = _security__lookupaccountsid($aret[4])
	If IsArray($aownersecinfo) AND $aownersecinfo[1] <> "BUILTIN" Then
		$sowner = $aownersecinfo[0]
	Else
		$agroupsecinfo = _security__lookupaccountsid($aret[5])
		If IsArray($agroupsecinfo) Then $sowner = $agroupsecinfo[0]
		If $sowner = "None" Then $sowner = @UserName
	EndIf
	$aret = DllCall($_common_kernel32dll, "handle", "LocalFree", "handle", $aret[8])
	If @error Then
		SetError(-2, @error)
	ElseIf $aret[0] Then
		SetError(-3, $aret[0])
	EndIf
	Return $sowner
EndFunc

Func _processgethandlecount($hprocess)
	If NOT IsPtr($hprocess) Then Return SetError(1, 0, -1)
	Local $aret = DllCall($_common_kernel32dll, "bool", "GetProcessHandleCount", "handle", $hprocess, "dword*", 0)
	If @error Then Return SetError(2, @error, -1)
	If NOT $aret[0] Then Return SetError(3, @error, -1)
	Return $aret[2]
EndFunc

Func _processgetiocounters($hprocess, $icountertoget = -1)
	If NOT IsPtr($hprocess) OR $icountertoget > 5 Then Return SetError(1, 0, -1)
	Local $stiocounters = DllStructCreate("uint64;uint64;uint64;uint64;uint64;uint64")
	Local $aret = DllCall($_common_kernel32dll, "bool", "GetProcessIoCounters", "handle", $hprocess, "ptr", DllStructGetPtr($stiocounters))
	If @error Then Return SetError(2, @error, -1)
	If NOT $aret[0] Then Return SetError(3, @error, -1)
	If $icountertoget < 0 Then
		Dim $acounterinfo[6]
		For $i = 0 To 5
			$acounterinfo[$i] = DllStructGetData($stiocounters, $i + 1)
		Next
		Return $acounterinfo
	EndIf
	Return DllStructGetData($stiocounters, $icountertoget + 1)
EndFunc

Func _processgetguiresources($hprocess, $iobjtype)
	If NOT IsPtr($hprocess) OR $iobjtype < 0 OR $iobjtype > 4 Then Return SetError(1, 0, -1)
	Local $aret = DllCall($_common_user32dll, "dword", "GetGuiResources", "handle", $hprocess, "dword", $iobjtype)
	If @error Then Return SetError(2, @error, -1)
	Return $aret[0]
EndFunc

Func _processgetfilename($hprocess, $vpsapidll = -1)
	If NOT IsPtr($hprocess) Then Return SetError(1, 0, "")
	Local $aret
	If NOT IsString($vpsapidll) AND $vpsapidll < 0 Then $vpsapidll = @SystemDir & "\psapi.dll"
	If @OSVersion = "WIN_2000" Then
		$aret = DllCall($vpsapidll, "dword", "GetModuleBaseNameW", "handle", $hprocess, "handle", 0, "wstr", 0, "dword", 65536)
		If @error Then Return SetError(2, @error, "")
		If NOT $aret[0] Then Return SetError(3, 0, "")
		Return $aret[3]
	EndIf
	$aret = DllCall($vpsapidll, "dword", "GetProcessImageFileNameW", "handle", $hprocess, "wstr", "", "dword", 65536)
	If @error Then Return SetError(2, @error, "")
	If NOT $aret[0] Then Return SetError(3, 0, "")
	Return StringMid($aret[2], StringInStr($aret[2], "\", 1, -1) + 1)
EndFunc

Func _processgetfilenamebypid($vprocessid)
	If NOT __pfenforcepid($vprocessid) Then Return SetError(1, 0, "")
	Local $aproclist = ProcessList()
	If @error Then Return SetError(2, @error, "")
	For $i = 1 To $aproclist[0][0]
		If $vprocessid = $aproclist[$i][1] Then Return $aproclist[$i][0]
	Next
	Return SetError(4, 0, "")
EndFunc

Func _processgetpathname($hprocess, $bresetdrivemap = False, $vpsapidll = -1)
	If NOT IsPtr($hprocess) Then Return SetError(1, 0, "")
	If NOT IsString($vpsapidll) AND $vpsapidll < 0 Then $vpsapidll = @SystemDir & "\psapi.dll"
	Local $aret
	If @OSVersion <> "WIN_XP" AND @OSVersion <> "WIN_XPe" AND @OSVersion <> "WIN_2003" Then
		If @OSVersion = "WIN_2000" Then
			$aret = DllCall($vpsapidll, "dword", "GetModuleFileNameExW", "handle", $hprocess, "handle", 0, "wstr", "", "dword", 65536)
		Else
			$aret = DllCall($_common_kernel32dll, "bool", "QueryFullProcessImageNameW", "handle", $hprocess, "dword", 0, "wstr", "", "dword*", 65536)
		EndIf
		If @error Then Return SetError(2, @error, "")
		If NOT $aret[0] Then Return SetError(3, 0, "")
		Return $aret[3]
	EndIf
	$aret = DllCall($vpsapidll, "dword", "GetProcessImageFileNameW", "handle", $hprocess, "wstr", "", "dword", 65536)
	If @error Then Return SetError(2, @error, "")
	If NOT $aret[0] Then Return SetError(3, 0, "")
	$aret = __pfxlatedevicepathname($aret[2], $bresetdrivemap)
	SetError(@error, @extended)
	Return $aret
EndFunc

Func _processwaitforinputidle($hprocess, $itimeout)
	If NOT IsPtr($hprocess) Then Return SetError(1, 0, False)
	Local $aret = DllCall($_common_user32dll, "int", "WaitForInputIdle", "handle", $hprocess, "dword", $itimeout)
	If @error Then Return SetError(2, @error, False)
	If $aret[0] Then Return SetError(3, $aret[0], False)
	Return True
EndFunc

Func _processgetmeminfo($hprocess, $iinfotoget = -1, $vpsapidll = -1)
	If NOT IsPtr($hprocess) OR $iinfotoget > 8 Then Return SetError(1, 0, -1)
	Local $stmemcounters = DllStructCreate("dword;dword;ulong_ptr;ulong_ptr;ulong_ptr;ulong_ptr;ulong_ptr;ulong_ptr;ulong_ptr;ulong_ptr")
	If NOT IsString($vpsapidll) AND $vpsapidll < 0 Then $vpsapidll = @SystemDir & "\psapi.dll"
	Local $aret = DllCall($vpsapidll, "bool", "GetProcessMemoryInfo", "handle", $hprocess, "ptr", DllStructGetPtr($stmemcounters), "dword", DllStructGetSize($stmemcounters))
	If @error Then Return SetError(2, @error, -1)
	If NOT $aret[0] Then Return SetError(3, 0, -1)
	If $iinfotoget < 0 Then
		Dim $ameminfo[9]
		For $i = 0 To 8
			$ameminfo[$i] = DllStructGetData($stmemcounters, $i + 2)
		Next
		Return $ameminfo
	EndIf
	Return DllStructGetData($stmemcounters, $iinfotoget + 2)
EndFunc

Func _processemptyworkingset($hprocess, $vpsapidll = -1)
	If NOT IsPtr($hprocess) Then Return SetError(1, 0, False)
	If NOT IsString($vpsapidll) AND $vpsapidll < 0 Then $vpsapidll = @SystemDir & "\psapi.dll"
	Local $aret = DllCall($vpsapidll, "bool", "EmptyWorkingSet", "handle", $hprocess)
	If @error Then Return SetError(2, @error, False)
	Return $aret[0]
EndFunc

Func _processmemoryread($hprocess, $psource, $pdest, $inumbytes)
	If NOT IsPtr($hprocess) OR Ptr($psource) = 0 OR NOT IsPtr($pdest) OR $inumbytes <= 0 Then Return SetError(1, 0, False)
	Local $aret = DllCall($_common_kernel32dll, "bool", "ReadProcessMemory", "handle", $hprocess, "ptr", $psource, "ptr", $pdest, "ulong_ptr", $inumbytes, "ulong_ptr*", 0)
	If @error Then Return SetError(2, @error, False)
	If NOT $aret[0] Then Return SetError(3, $aret[5], False)
	Return SetExtended($aret[5], True)
EndFunc

Func _processmemoryreadsimple($hprocess, $psource, $inumbytes, $stype)
	If NOT IsPtr($hprocess) OR Ptr($psource) = 0 OR $inumbytes <= 0 Then Return SetError(1, 0, "")
	If StringRight($stype, 3) <> "str" Then $stype &= "*"
	Local $aret = DllCall($_common_kernel32dll, "bool", "ReadProcessMemory", "handle", $hprocess, "ptr", $psource, $stype, "", "ulong_ptr", $inumbytes, "ulong_ptr*", 0)
	If @error Then Return SetError(2, @error, False)
	If $aret[0] Then Return SetExtended($aret[5], $aret[3])
	Return SetError(3, $aret[5], $aret[3])
EndFunc

Func _processmemorywrite($hprocess, $pdest, $psource, $inumbytes)
	If NOT IsPtr($hprocess) OR NOT IsPtr($psource) OR Ptr($pdest) = 0 OR $inumbytes <= 0 Then Return SetError(1, 0, False)
	Local $aret = DllCall($_common_kernel32dll, "bool", "WriteProcessMemory", "handle", $hprocess, "ptr", $pdest, "ptr", $psource, "ulong_ptr", $inumbytes, "ulong_ptr*", 0)
	If @error Then Return SetError(2, @error, False)
	If NOT $aret[0] Then Return SetError(3, 0, False)
	Return SetExtended($aret[5], True)
EndFunc

Func _processmemorywritesimple($hprocess, $pdest, $inumbytes, $stype)
	If NOT IsPtr($hprocess) OR Ptr($pdest) = 0 OR $inumbytes <= 0 Then Return SetError(1, 0, False)
	If StringRight($stype, 3) <> "str" Then $stype &= "*"
	Local $aret = DllCall($_common_kernel32dll, "bool", "WriteProcessMemory", "handle", $hprocess, "ptr", $pdest, $stype, "", "ulong_ptr", $inumbytes, "ulong_ptr*", 0)
	If @error Then Return SetError(2, @error, False)
	If NOT $aret[0] Then Return SetError(3, 0, False)
	Return SetExtended($aret[5], True)
EndFunc

Func _processmemoryalloc($hprocess, $inumbytes, $ialloctype, $iprotecttype, $paddress = 0)
	If NOT IsPtr($hprocess) Then Return SetError(1, 0, 0)
	Local $aret = DllCall($_common_kernel32dll, "ptr", "VirtualAllocEx", "handle", $hprocess, "ptr", $paddress, "ulong_ptr", $inumbytes, "dword", $ialloctype, "dword", $iprotecttype)
	If @error Then Return SetError(2, @error, 0)
	If $aret[0] = 0 Then Return SetError(3, 0, 0)
	Return $aret[0]
EndFunc

Func _processmemoryfree($hprocess, ByRef $paddress, $inumbytes = 0, $ifreetype = 32768)
	If NOT IsPtr($hprocess) OR NOT IsPtr($paddress) Then Return SetError(1, 0, False)
	Local $aret = DllCall($_common_kernel32dll, "bool", "VirtualFreeEx", "handle", $hprocess, "ptr", $paddress, "ulong_ptr", $inumbytes, "dword", $ifreetype)
	If @error Then Return SetError(2, @error, False)
	If NOT $aret[0] Then Return SetError(3, 0, False)
	If $ifreetype = 32768 Then $paddress = 0
	Return True
EndFunc

Func _processmemoryvirtualquery($hprocess, $paddress, $iinfo = -1)
	If NOT IsPtr($hprocess) OR Ptr($paddress) = 0 OR $iinfo > 6 Then Return SetError(1, 0, -1)
	Local $aret, $stmeminfo = DllStructCreate("ptr;ptr;dword;ulong_ptr;dword;dword;dword"), $istrsz = DllStructGetSize($stmeminfo)
	$aret = DllCall($_common_kernel32dll, "ulong_ptr", "VirtualQueryEx", "handle", $hprocess, "ptr", $paddress, "ptr", DllStructGetPtr($stmeminfo), "ulong_ptr", $istrsz)
	If @error Then Return SetError(2, @error, -1)
	If NOT $aret[0] Then Return SetError(3, @error, -1)
	If $aret[0] <> $istrsz Then ConsoleWriteError("Size (in bytes) mismatch in VirtualQueryEx: Struct: " & $istrsz & ", Transferred: " & $aret[0] & @LF)
	If $iinfo < 0 Then
		Dim $ameminfo[7]
		For $i = 0 To 6
			$ameminfo[$i] = DllStructGetData($stmeminfo, $i + 1)
		Next
		Return $ameminfo
	EndIf
	Return DllStructGetData($stmeminfo, $iinfo + 1)
EndFunc

Func _processmemoryvirtualprotect($hprocess, $paddress, $inumbytes, $iprotect)
	If NOT IsPtr($hprocess) OR Ptr($paddress) = 0 OR $inumbytes <= 0 Then Return SetError(1, 0, False)
	Local $aret = DllCall($_common_kernel32dll, "bool", "VirtualProtectEx", "handle", $hprocess, "ptr", $paddress, "ulong_ptr", $inumbytes, "dword", $iprotect, "dword*", 0)
	If @error Then Return SetError(2, @error, False)
	If NOT $aret[0] Then Return SetError(3, 0, False)
	Return SetError(0, $aret[5], True)
EndFunc

Func _processterminate($hprocess, $iexitcode = 0)
	If NOT IsPtr($hprocess) Then Return SetError(1, 0, False)
	Local $aret = DllCall($_common_kernel32dll, "bool", "TerminateProcess", "handle", $hprocess, "int", $iexitcode)
	If @error Then Return SetError(2, @error, False)
	If NOT $aret[0] Then Return SetError(3, 0, False)
	Return True
EndFunc

Func __dll_getmodulehandleex($vmodule, $iflags, $vmoduletype = "wstr")
	Local $aret = DllCall($_common_kernel32dll, "bool", "GetModuleHandleExW", "dword", $iflags, $vmoduletype, $vmodule, "handle*", 0)
	If @error Then Return SetError(2, @error, 0)
	If NOT $aret[0] Then Return SetError(3, 0, 0)
	Return $aret[3]
EndFunc

Func _dll_gethandlefromaddress($paddress)
	If Ptr($paddress) = 0 Then Return SetError(1, 0, 0)
	Local $vret = __dll_getmodulehandleex($paddress, 6, "ptr")
	Return SetError(@error, @extended, $vret)
EndFunc

Func _dll_forcepermanentload($vmodule)
	Local $vret, $stype, $iflags = 1
	If IsPtr($vmodule) Then
		$stype = "ptr"
		$iflags += 4
	ElseIf IsString($vmodule) Then
		$stype = "wstr"
	Else
		Return SetError(1, 0, 0)
	EndIf
	$vret = __dll_getmodulehandleex($vmodule, $iflags, $stype)
	Return SetError(@error, @extended, $vret)
EndFunc

Func _dll_getloadedlibraryhandle($sdllname = 0)
	If NOT IsString($sdllname) AND $sdllname <> 0 Then Return SetError(1, 0, 0)
	Local $aret, $stype = "wstr"
	If $sdllname = 0 Then $stype = "ptr"
	$aret = DllCall($_common_kernel32dll, "handle", "GetModuleHandleW", $stype, $sdllname)
	If @error Then Return SetError(2, @error, 0)
	If $aret = 0 Then Return SetError(3, 0, 0)
	Return $aret[0]
EndFunc

Func _dll_getmodulefilename($hdllmodule)
	If NOT IsPtr($hdllmodule) Then Return SetError(1, 0, "")
	Local $aret = DllCall($_common_kernel32dll, "dword", "GetModuleFileNameW", "handle", $hdllmodule, "wstr", "", "dword", 65536)
	If @error Then Return SetError(2, @error, 0)
	If $aret = 0 Then Return SetError(3, 0, 0)
	If StringLeft($aret[2], 4) = "\\?\" Then Return StringTrimLeft($aret[2], 4)
	Return $aret[2]
EndFunc

Func _dll_loadlibrary($sdllname)
	If NOT IsString($sdllname) Then Return SetError(1, 0, 0)
	Local $aret = DllCall($_common_kernel32dll, "handle", "LoadLibraryW", "wstr", $sdllname)
	If @error Then Return SetError(2, @error, 0)
	If NOT $aret[0] Then Return SetError(3, 0, 0)
	Return $aret[0]
EndFunc

Func _dll_freelibrary(ByRef $hdllmodule)
	If NOT IsPtr($hdllmodule) Then Return SetError(1, 0, 0)
	Local $aret = DllCall($_common_kernel32dll, "bool", "FreeLibrary", "handle", $hdllmodule)
	If @error Then Return SetError(2, @error, 0)
	If NOT $aret[0] Then Return SetError(3, 0, 0)
	$hdllmodule = 0
	Return $aret[0]
EndFunc

Func _dll_getprocaddress($hdllmodule, $vprocname)
	If NOT IsPtr($hdllmodule) Then Return SetError(1, 0, 0)
	Local $aret, $sproctype
	If StringIsDigit($vprocname) Then
		$sproctype = "long_ptr"
	ElseIf IsString($vprocname) Then
		$sproctype = "str"
	Else
		Return SetError(1, 0, 0)
	EndIf
	$aret = DllCall($_common_kernel32dll, "ptr", "GetProcAddress", "handle", $hdllmodule, $sproctype, $vprocname)
	If @error Then Return SetError(2, @error, 0)
	If NOT $aret[0] Then Return SetError(3, 0, 0)
	Return $aret[0]
EndFunc

Func _dll_getbaseandprocaddresses($sdllname, $sfuncs, $ssep = ";", $bunloaddll = True)
	Local $pfunc, $hdllmodule, $afuncs, $aptrs, $ierr = 0, $iext, $itotal = 0
	$hdllmodule = _dll_loadlibrary($sdllname)
	If @error Then Return SetError(@error, @extended, "")
	$afuncs = StringSplit($sfuncs, $ssep, 1)
	Dim $aptrs[$afuncs[0] + 1]
	$aptrs[0] = $hdllmodule
	For $i = 1 To $afuncs[0]
		$pfunc = _dll_getprocaddress($hdllmodule, $afuncs[$i])
		If @error Then
			$ierr = @error
			$iext = @extended
			ExitLoop 
		EndIf
		$aptrs[$i] = $pfunc
		$itotal += 1
	Next
	If $bunloaddll OR $ierr Then _dll_freelibrary($hdllmodule)
	If $ierr Then Return SetError($ierr, $iext, "")
	Return SetExtended($itotal, $aptrs)
EndFunc

Func _dll_getbaseandprocaddress($sdllname, $vprocname, $bunloaddll = True)
	Local $aptrs = _dll_getbaseandprocaddresses($sdllname, $vprocname, $bunloaddll)
	If @error Then Return SetError(@error, @extended, "")
	If @extended > 1 Then ReDim $aptrs[2]
	Return $aptrs
EndFunc

Func __pfcreatetoolhelp32snapshot($iprocessid, $iflags)
	Local $aret
	For $i = 1 To 10
		$aret = DllCall($_common_kernel32dll, "handle", "CreateToolhelp32Snapshot", "dword", $iflags, "dword", $iprocessid)
		If @error Then Return SetError(2, @error, -1)
		If $aret[0] = -1 Then
			If BitAND($iflags, 25) AND _winapi_getlasterror() = 24 Then ContinueLoop 
			Return SetError(3, 0, -1)
		EndIf
		Sleep(0)
	Next
	If $aret[0] = -1 Then Return SetError(4, 0, -1)
	Return $aret[0]
EndFunc

Func _processlistex($vfilter = 0, $imatchmode = 0)
	Local $htlhlp, $aret, $ipid, $ippid, $stitle
	Local $bmatchmade = 1, $itotal = 0, $iarrsz = 100, $aprocesses[$iarrsz + 1][5], $bfilteron = 0, $ineg = 0
	Local $stprocentry = DllStructCreate("dword;dword;dword;ulong_ptr;dword;dword;dword;long;dword;wchar[260]"), $pstpointer = DllStructGetPtr($stprocentry)
	DllStructSetData($stprocentry, 1, DllStructGetSize($stprocentry))
	If (IsString($vfilter) AND $vfilter <> "") OR (IsNumber($vfilter) AND $imatchmode > 2) Then $bfilteron = 1
	If BitAND($imatchmode, 8) Then
		$ineg = -1
		$imatchmode = BitAND($imatchmode, 7)
	EndIf
	$htlhlp = __pfcreatetoolhelp32snapshot(0, 1073741826)
	If @error Then Return SetError(@error, @extended, "")
	$aret = DllCall($_common_kernel32dll, "bool", "Process32FirstW", "handle", $htlhlp, "ptr", $pstpointer)
	While 1
		If @error Then
			Local $ierr = @error
			__pfclosehandle($htlhlp)
			Return SetError(2, $ierr, "")
		EndIf
		If NOT $aret[0] Then ExitLoop 
		$stitle = DllStructGetData($stprocentry, 10)
		$ipid = DllStructGetData($stprocentry, 3)
		$ippid = DllStructGetData($stprocentry, 7)
		If $bfilteron Then
			Switch $imatchmode
				Case 0
					If $vfilter <> $stitle Then $bmatchmade = 0
				Case 1
					If StringInStr($stitle, $vfilter) = 0 Then $bmatchmade = 0
				Case 2
					If NOT StringRegExp($stitle, $vfilter) Then $bmatchmade = 0
				Case 3
					If $vfilter <> $ipid Then $bmatchmade = 0
				Case Else
					If $vfilter <> $ippid Then $bmatchmade = 0
			EndSwitch
			$bmatchmade += $ineg
		EndIf
		If $bmatchmade Then
			$itotal += 1
			If $itotal > $iarrsz Then
				$iarrsz += 10
				ReDim $aprocesses[$iarrsz + 1][5]
			EndIf
			$aprocesses[$itotal][0] = $stitle
			$aprocesses[$itotal][1] = $ipid
			$aprocesses[$itotal][2] = $ippid
			$aprocesses[$itotal][3] = DllStructGetData($stprocentry, 6)
			$aprocesses[$itotal][4] = DllStructGetData($stprocentry, 8)
			If $bfilteron AND $imatchmode = 3 Then ExitLoop 
		EndIf
		$bmatchmade = 1
		$aret = DllCall($_common_kernel32dll, "bool", "Process32NextW", "handle", $htlhlp, "ptr", $pstpointer)
	WEnd
	__pfclosehandle($htlhlp)
	ReDim $aprocesses[$itotal + 1][5]
	$aprocesses[0][0] = $itotal
	Return $aprocesses
EndFunc

Func _processgetchildren($vprocessid)
	If NOT __pfenforcepid($vprocessid) Then Return SetError(1, 0, "")
	Local $aproclist = _processlistex($vprocessid, 4)
	Return SetError(@error, @extended, $aproclist)
EndFunc

Func _processgetparent($vprocessid)
	Local $i, $aproclist, $aparentinfo[5], $iparentpid
	If NOT __pfenforcepid($vprocessid) Then Return SetError(1, 0, "")
	$aproclist = _processlistex($vprocessid, 3)
	If @error Then Return SetError(@error, @extended, "")
	If $aproclist[0][0] = 0 Then Return SetError(32, 0, "")
	$iparentpid = $aproclist[1][2]
	$aproclist = _processlistex($iparentpid, 3)
	If @error Then Return SetError(@error, @extended, "")
	If $aproclist[0][0] = 0 Then Return SetError(16, $iparentpid, "")
	For $i = 0 To 4
		$aparentinfo[$i] = $aproclist[1][$i]
	Next
	Return $aparentinfo
EndFunc

Func _processlistheaps($vprocessid, $bheapwalk = False, $bcompletelist = False)
	If $bcompletelist AND NOT $bheapwalk Then Return SetError(1, 0, "")
	If NOT __pfenforcepid($vprocessid) Then Return SetError(1, 0, "")
	Local $htlhlp, $aret, $ierr, $iheapid, $itotal = 0, $iheapsz, $iheaptotalsz, $iarrsz = 20
	If $bcompletelist Then $iarrsz = 5000
	Dim $aheaplist[$iarrsz + 1][5]
	Local $stheaplist = DllStructCreate("ulong_ptr;dword;ulong_ptr;dword"), $phlpointer = DllStructGetPtr($stheaplist)
	DllStructSetData($stheaplist, 1, DllStructGetSize($stheaplist))
	Local $stheapentry = DllStructCreate("ulong_ptr;handle;ptr;ulong_ptr;dword;dword;dword;dword;ulong_ptr"), $phepointer = DllStructGetPtr($stheapentry)
	DllStructSetData($stheapentry, 1, DllStructGetSize($stheapentry))
	$htlhlp = __pfcreatetoolhelp32snapshot($vprocessid, 1)
	If @error Then Return SetError(@error, @extended, "")
	$aret = DllCall($_common_kernel32dll, "bool", "Heap32ListFirst", "handle", $htlhlp, "ptr", $phlpointer)
	While 1
		If @error Then
			$ierr = @error
			__pfclosehandle($htlhlp)
			Return SetError(2, $ierr, "")
		EndIf
		If NOT $aret[0] Then ExitLoop 
		$iheapid = DllStructGetData($stheaplist, 3)
		$iheaptotalsz = 0
		$aret = DllCall($_common_kernel32dll, "bool", "Heap32First", "ptr", $phepointer, "dword", $vprocessid, "ulong_ptr", $iheapid)
		While 1
			If @error Then
				$ierr = @error
				__pfclosehandle($htlhlp)
				Return SetError(6, $ierr, "")
			EndIf
			If NOT $aret[0] Then ExitLoop 
			$iheapsz = DllStructGetData($stheapentry, 4)
			If $bcompletelist OR $iheaptotalsz = 0 Then
				$itotal += 1
				If $itotal > $iarrsz Then
					$iarrsz += 1000
					ReDim $aheaplist[$iarrsz + 1][5]
				EndIf
				$aheaplist[$itotal][0] = DllStructGetData($stheapentry, 2)
				$aheaplist[$itotal][1] = DllStructGetData($stheapentry, 3)
				If $bcompletelist Then $aheaplist[$itotal][2] = $iheapsz
				$aheaplist[$itotal][3] = DllStructGetData($stheapentry, 5)
				$aheaplist[$itotal][4] = $iheapid
			EndIf
			If NOT $bheapwalk Then ExitLoop 
			$iheaptotalsz += $iheapsz
			$aret = DllCall($_common_kernel32dll, "bool", "Heap32Next", "ptr", $phepointer)
		WEnd
		If $bheapwalk AND NOT $bcompletelist Then $aheaplist[$itotal][2] = $iheaptotalsz
		$aret = DllCall($_common_kernel32dll, "bool", "Heap32ListNext", "handle", $htlhlp, "ptr", $phlpointer)
	WEnd
	__pfclosehandle($htlhlp)
	ReDim $aheaplist[$itotal + 1][5]
	$aheaplist[0][0] = $itotal
	Return $aheaplist
EndFunc

Func _processlistthreads($vfilterid = -1, $bthreadfilter = False)
	If IsString($vfilterid) AND NOT StringIsDigit($vfilterid) Then
		If $bthreadfilter Then Return SetError(1, 0, "")
		$vfilterid = ProcessExists($vfilterid)
		If $vfilterid = 0 Then Return SetError(1, 0, "")
	EndIf
	Local $htlhlp, $aret, $icurpid, $icurtid, $itotal = 0, $iarrsz = 500, $athreads[$iarrsz + 1][3]
	Local $stthreadentry = DllStructCreate("dword;dword;dword;dword;long;long;dword"), $ptepointer = DllStructGetPtr($stthreadentry)
	DllStructSetData($stthreadentry, 1, DllStructGetSize($stthreadentry))
	$htlhlp = __pfcreatetoolhelp32snapshot(0, 4)
	If @error Then Return SetError(@error, @extended, "")
	$aret = DllCall($_common_kernel32dll, "bool", "Thread32First", "handle", $htlhlp, "ptr", $ptepointer)
	While 1
		If @error Then
			Local $ierr = @error
			__pfclosehandle($htlhlp)
			Return SetError(2, $ierr, "")
		EndIf
		If NOT $aret[0] Then ExitLoop 
		$icurpid = DllStructGetData($stthreadentry, 4)
		$icurtid = DllStructGetData($stthreadentry, 3)
		If $vfilterid < 0 OR (NOT $bthreadfilter AND $vfilterid = $icurpid) OR ($bthreadfilter AND $vfilterid = $icurtid) Then
			$itotal += 1
			If $itotal > $iarrsz Then
				$iarrsz += 50
				ReDim $athreads[$iarrsz + 1][3]
			EndIf
			$athreads[$itotal][0] = $icurtid
			$athreads[$itotal][1] = $icurpid
			$athreads[$itotal][2] = DllStructGetData($stthreadentry, 5)
			If $bthreadfilter Then ExitLoop 
		EndIf
		$aret = DllCall($_common_kernel32dll, "bool", "Thread32Next", "handle", $htlhlp, "ptr", $ptepointer)
	WEnd
	__pfclosehandle($htlhlp)
	ReDim $athreads[$itotal + 1][3]
	$athreads[0][0] = $itotal
	Return $athreads
EndFunc

Func _processlistmodules($vprocessid, $stitlefilter = 0, $ititlematchmode = 0, $blist32bitmods = False)
	If NOT __pfenforcepid($vprocessid) Then Return SetError(1, 0, "")
	Local $htlhlp, $aret, $stitle, $bmatchmade = 1, $itotal = 0, $bmatch1 = 0, $iarrsz = 40, $ineg = 0
	If $stitlefilter = "" Then $stitlefilter = 0
	If BitAND($ititlematchmode, 8) Then
		$ineg = -1
	ElseIf BitAND($ititlematchmode, 4) AND IsString($stitlefilter) Then
		$iarrsz = 1
		$bmatch1 = 1
	EndIf
	$ititlematchmode = BitAND($ititlematchmode, 3)
	Dim $amodules[$iarrsz + 1][6]
	Local $stmodentry = DllStructCreate("dword;dword;dword;dword;dword;ptr;dword;handle;wchar[256];wchar[260]"), $pmepointer = DllStructGetPtr($stmodentry)
	DllStructSetData($stmodentry, 1, DllStructGetSize($stmodentry))
	If $blist32bitmods Then
		$htlhlp = __pfcreatetoolhelp32snapshot($vprocessid, 24)
	Else
		$htlhlp = __pfcreatetoolhelp32snapshot($vprocessid, 8)
	EndIf
	If @error Then Return SetError(@error, @extended, "")
	$aret = DllCall($_common_kernel32dll, "bool", "Module32FirstW", "handle", $htlhlp, "ptr", $pmepointer)
	While 1
		If @error Then
			Local $ierr = @error
			__pfclosehandle($htlhlp)
			Return SetError(2, $ierr, "")
		EndIf
		If NOT $aret[0] Then ExitLoop 
		$stitle = DllStructGetData($stmodentry, 9)
		If IsString($stitlefilter) Then
			Switch $ititlematchmode
				Case 0
					If $stitlefilter <> $stitle Then $bmatchmade = 0
				Case 1
					If StringInStr($stitle, $stitlefilter) = 0 Then $bmatchmade = 0
				Case Else
					If NOT StringRegExp($stitle, $stitlefilter) Then $bmatchmade = 0
			EndSwitch
			$bmatchmade += $ineg
		EndIf
		If $bmatchmade Then
			$itotal += 1
			If $itotal > $iarrsz Then
				$iarrsz += 10
				ReDim $amodules[$iarrsz + 1][6]
			EndIf
			$amodules[$itotal][0] = $stitle
			$amodules[$itotal][1] = DllStructGetData($stmodentry, 10)
			$amodules[$itotal][2] = DllStructGetData($stmodentry, 8)
			$amodules[$itotal][3] = DllStructGetData($stmodentry, 6)
			$amodules[$itotal][4] = DllStructGetData($stmodentry, 7)
			$amodules[$itotal][5] = DllStructGetData($stmodentry, 5)
			If $bmatch1 Then ExitLoop 
		EndIf
		$bmatchmade = 1
		$aret = DllCall($_common_kernel32dll, "bool", "Module32NextW", "handle", $htlhlp, "ptr", $pmepointer)
	WEnd
	__pfclosehandle($htlhlp)
	ReDim $amodules[$itotal + 1][6]
	$amodules[0][0] = $itotal
	Return $amodules
EndFunc

Func _processgetmodulebaseaddress($vprocessid, $smodulename, $blist32bitmods = False, $bgetwow64instance = False)
	Local $i = 0, $amodlist
	If NOT $blist32bitmods Then $i = 4
	$amodlist = _processlistmodules($vprocessid, $smodulename, $i, $blist32bitmods)
	If @error Then Return SetError(@error, @extended, -1)
	If $amodlist[0][0] = 0 Then Return SetError(-1, 0, -1)
	If $amodlist[0][0] > 1 Then
		If $blist32bitmods AND $bgetwow64instance Then Return SetExtended($amodlist[2][4], $amodlist[2][3])
		SetError(-16)
	EndIf
	Return SetError(@error, $amodlist[1][4], $amodlist[1][3])
EndFunc

Func _processgetmodulebyaddress($vprocessid, $paddress)
	If Ptr($paddress) = 0 Then Return SetError(1, 0, "")
	Local $iaddress, $imodaddress, $amodlist, $areturn[6]
	$amodlist = _processlistmodules($vprocessid, 0, 0, True)
	If @error Then Return SetError(@error, @extended, "")
	$iaddress = Int($paddress & "")
	For $i = 1 To $amodlist[0][0]
		$imodaddress = Int($amodlist[$i][3] & "")
		If $iaddress >= $imodaddress AND $iaddress < ($imodaddress + $amodlist[$i][4]) Then
			For $i2 = 0 To 5
				$areturn[$i2] = $amodlist[$i][$i2]
			Next
			Return $areturn
		EndIf
	Next
	Return SetError(16, 0, "")
EndFunc

Func _processlistwts($vfilter = 0, $imatchmode = 0, $vwtsapi32dll = "wtsapi32.dll")
	If $vwtsapi32dll < 0 Then Return SetError(1, 0, "")
	Local $aret, $itotalstructs, $stitle, $ipid, $pwtsbase
	Local $ioffset = 0, $asidinfo, $bmatchmade = 1, $itotal = 0, $bfilteron = 0, $ineg = 0
	Local $stwtsprocinfo, $istructsz = DllStructGetSize(DllStructCreate("dword;dword;ptr;ptr"))
	Local $ststbuf = DllStructCreate("wchar[260]"), $pstbuf = DllStructGetPtr($ststbuf)
	If (IsString($vfilter) AND $vfilter <> "") OR (IsNumber($vfilter) AND $imatchmode > 2) Then $bfilteron = 1
	If BitAND($imatchmode, 8) Then
		$ineg = -1
		$imatchmode = BitAND($imatchmode, 3)
	EndIf
	$aret = DllCall($vwtsapi32dll, "bool", "WTSEnumerateProcessesW", "handle", 0, "dword", 0, "dword", 1, "ptr*", 0, "dword*", 0)
	If @error Then Return SetError(2, @error, "")
	If NOT $aret[0] Then Return SetError(3, 0, "")
	$itotalstructs = $aret[5]
	Dim $aproclist[$itotalstructs + 1][4]
	$pwtsbase = $aret[4]
	For $i = 1 To $itotalstructs
		$stwtsprocinfo = DllStructCreate("dword;dword;ptr;ptr", $pwtsbase + $ioffset)
		$aret = DllCall($_common_kernel32dll, "ptr", "lstrcpynW", "ptr", $pstbuf, "ptr", DllStructGetData($stwtsprocinfo, 3), "int", 260)
		If @error OR $aret[0] = 0 Then DllStructSetData($ststbuf, 1, "")
		$stitle = DllStructGetData($ststbuf, 1)
		$ipid = DllStructGetData($stwtsprocinfo, 2)
		If $bfilteron Then
			Switch $imatchmode
				Case 0
					If $vfilter <> $stitle Then $bmatchmade = 0
				Case 1
					If StringInStr($stitle, $vfilter) = 0 Then $bmatchmade = 0
				Case 2
					If NOT StringRegExp($stitle, $vfilter) Then $bmatchmade = 0
				Case Else
					If $vfilter <> $ipid Then $bmatchmade = 0
			EndSwitch
			$bmatchmade += $ineg
		EndIf
		If $bmatchmade Then
			$itotal += 1
			$aproclist[$itotal][0] = $stitle
			$aproclist[$itotal][1] = $ipid
			$aproclist[$itotal][2] = DllStructGetData($stwtsprocinfo, 1)
			$asidinfo = _security__lookupaccountsid(DllStructGetData($stwtsprocinfo, 4))
			If IsArray($asidinfo) Then $aproclist[$itotal][3] = $asidinfo[0]
			If $bfilteron AND $imatchmode = 3 Then ExitLoop 
		EndIf
		$bmatchmade = 1
		$ioffset += $istructsz
	Next
	If $itotal AND $aproclist[1][1] = 0 Then
		$aproclist[1][0] = "[System Process]"
		$aproclist[1][3] = "SYSTEM"
	EndIf
	If $itotal > 1 AND $aproclist[2][0] = "System" Then $aproclist[2][3] = "SYSTEM"
	DllCall($vwtsapi32dll, "none", "WTSFreeMemory", "ptr", $pwtsbase)
	If @error Then SetExtended(@error)
	ReDim $aproclist[$itotal + 1][4]
	$aproclist[0][0] = $itotal
	Return $aproclist
EndFunc

Func _processwinlist($vprocessid, $stitle = 0, $bonlygetvisible = False, $bonlygetroot = False, $bonlygetalttab = False)
	If NOT __pfenforcepid($vprocessid) Then Return SetError(1, 0, "")
	If $bonlygetalttab Then $bonlygetvisible = 1
	Local $awinlist, $aenumlist, $hwndcur, $icount = 0, $icurmatchcriteria = 0, $itotalcriteriatomatch = 0, $iexstyle
	If IsString($stitle) Then
		$awinlist = WinList($stitle)
	Else
		$awinlist = WinList()
	EndIf
	Dim $aenumlist[$awinlist[0][0] + 1][2]
	If $bonlygetalttab Then
		$itotalcriteriatomatch += 1
		$bonlygetvisible = 1
	EndIf
	If $bonlygetvisible Then $itotalcriteriatomatch += 1
	If $bonlygetroot Then $itotalcriteriatomatch += 1
	For $i = 1 To $awinlist[0][0]
		$hwndcur = $awinlist[$i][1]
		If $vprocessid = WinGetProcess($hwndcur) Then
			If $bonlygetvisible AND BitAND(WinGetState($hwndcur), 2) = 2 Then $icurmatchcriteria += 1
			If $bonlygetroot AND _winapi_getancestor($hwndcur, 2) = $hwndcur Then $icurmatchcriteria += 1
			If $bonlygetalttab Then
				$iexstyle = _winapi_getwindowlong($hwndcur, -20)
				If BitAND($iexstyle, 134217856) = 0 OR BitAND($iexstyle, 262144) Then $icurmatchcriteria += 1
			EndIf
			If $icurmatchcriteria = $itotalcriteriatomatch Then
				$icount += 1
				$aenumlist[$icount][0] = $awinlist[$i][0]
				$aenumlist[$icount][1] = $hwndcur
			EndIf
			$icurmatchcriteria = 0
		EndIf
	Next
	$aenumlist[0][0] = $icount
	ReDim $aenumlist[$icount + 1][2]
	Return $aenumlist
EndFunc

Func _processeswinlist($sprocess, $stitle = 0, $bonlygetvisible = False, $bonlygetroot = False, $bonlygetalttab = False)
	Local $i, $i2, $awinlist, $aproclist, $icurpid, $icount = 0, $hwndcur, $icurmatchcriteria = 0, $itotalcriteriatomatch = 0, $iexstyle
	$aproclist = ProcessList($sprocess)
	If IsString($stitle) Then
		$awinlist = WinList($stitle)
	Else
		$awinlist = WinList()
	EndIf
	If $awinlist[0][0] = 0 Then Return SetError(16, 0, "")
	Dim $amatches[$awinlist[0][0] + 1][4]
	If $bonlygetalttab Then
		$itotalcriteriatomatch += 1
		$bonlygetvisible = 1
	EndIf
	If $bonlygetvisible Then $itotalcriteriatomatch += 1
	If $bonlygetroot Then $itotalcriteriatomatch += 1
	For $i = 1 To $awinlist[0][0]
		$hwndcur = $awinlist[$i][1]
		$icurpid = WinGetProcess($hwndcur)
		For $i2 = 1 To $aproclist[0][0]
			If $icurpid = $aproclist[$i2][1] Then
				If $bonlygetvisible AND BitAND(WinGetState($hwndcur), 2) = 2 Then $icurmatchcriteria += 1
				If $bonlygetroot AND _winapi_getancestor($hwndcur, 2) = $hwndcur Then $icurmatchcriteria += 1
				If $bonlygetalttab Then
					$iexstyle = _winapi_getwindowlong($hwndcur, -20)
					If BitAND($iexstyle, 134217856) = 0 OR BitAND($iexstyle, 262144) Then $icurmatchcriteria += 1
				EndIf
				If $icurmatchcriteria = $itotalcriteriatomatch Then
					$icount += 1
					$amatches[$icount][0] = $aproclist[$i2][0]
					$amatches[$icount][1] = $icurpid
					$amatches[$icount][2] = $awinlist[$i][0]
					$amatches[$icount][3] = $hwndcur
				EndIf
				$icurmatchcriteria = 0
				ExitLoop 
			EndIf
		Next
	Next
	If $icount = 0 Then Return SetError(32, 0, "")
	ReDim $amatches[$icount + 1][4]
	$amatches[0][0] = $icount
	Return $amatches
EndFunc

Func _processgetprocaddresses($iprocessid, $sdllname, $sfuncs, $ssep = ";", $blist32bitmods = False, $bgetwow64instance = False)
	Local $pextbase, $hdllmodule, $aptrs, $aextptrs, $itotal
	$pextbase = _processgetmodulebaseaddress($iprocessid, StringRegExpReplace($sdllname, "(.*?)([^\\]+)$", "$2"), $blist32bitmods, $bgetwow64instance)
	If @error Then Return SetError(@error, @extended, "")
	$aptrs = _dll_getbaseandprocaddresses($sdllname, $sfuncs, $ssep)
	If @error Then Return SetError(@error, @extended, "")
	$itotal = @extended
	Dim $aextptrs[$itotal + 1]
	$hdllmodule = $aptrs[0]
	$aextptrs[0] = $pextbase
	For $i = 1 To $itotal
		$aextptrs[$i] = $aptrs[$i] - $hdllmodule + $pextbase
	Next
	Return SetExtended($itotal, $aextptrs)
EndFunc

Func _processgetprocaddress($iprocessid, $sdllname, $sfunc, $blist32bitmods = False, $bgetwow64instance = False)
	Local $aextptrs = _processgetprocaddresses($iprocessid, $sdllname, $sfunc, $blist32bitmods, $bgetwow64instance)
	If @error Then Return SetError(@error, @extended, 0)
	Return SetExtended($aextptrs[0], $aextptrs[1])
EndFunc

Global Const $stub_x86_size = 16, $stub_x64_size = 32

Func _processgeneratethreadstub($hprocess, $iprocessid, $pcodeptr, $bwow64code = False)
	Local $iptrsize = 4, $sx64 = "", $pexitthread, $binstubcode, $ibinlen
	If @AutoItX64 Then
		If _processis32bit($hprocess) Then
			If NOT $bwow64code Then Return SetError(6432, 0, 0)
		Else
			If $bwow64code Then Return SetError(3264, 0, 0)
			$sx64 = "00000000"
			$iptrsize = 8
		EndIf
	Else
		If _processis64bit($hprocess) Then Return SetError(3264, 0, 0)
	EndIf
	If $iptrsize = 4 Then
		$binstubcode = "0x58B8FEEDFACEFFD050B8DECAFBADFFD0"
		$ibinlen = $stub_x86_size
	Else
		$binstubcode = "0x4883EC2848B8FEEDFACE00000000FFD04889C148B8DECAFBAD00000000FFD090"
		$ibinlen = $stub_x64_size
	EndIf
	$pexitthread = _processgetprocaddress($iprocessid, "kernel32.dll", "ExitThread", $bwow64code, $bwow64code)
	If @error AND @error <> -16 Then Return SetError(@error, @extended, 0)
	$binstubcode = Binary(StringReplace(StringReplace($binstubcode, "FEEDFACE" & $sx64, StringTrimLeft(BinaryMid($pcodeptr, 1, $iptrsize), 2)), "DECAFBAD" & $sx64, StringTrimLeft(BinaryMid($pexitthread, 1, $iptrsize), 2)))
	Return SetExtended($ibinlen, $binstubcode)
EndFunc

Func _processcreateremotethreadstub($hprocess, $iprocessid, $pcodeptr, $bwow64code = False)
	Local $prtlstub, $binstubcode, $stlocalstub, $ibinlen
	$binstubcode = _processgeneratethreadstub($hprocess, $iprocessid, $pcodeptr, $bwow64code)
	If @error Then Return SetError(@error, @extended, 0)
	$ibinlen = @extended
	$prtlstub = _processmemoryalloc($hprocess, $ibinlen, 4096, 64)
	If @error Then Return SetError(@error, @extended, 0)
	Local $stlocalstub = DllStructCreate("byte[" & $ibinlen & "]")
	DllStructSetData($stlocalstub, 1, $binstubcode)
	If NOT _processmemorywrite($hprocess, $prtlstub, DllStructGetPtr($stlocalstub), $ibinlen) Then
		Local $ierr = @error, $iext = @extended
		_processmemoryfree($hprocess, $prtlstub)
		Return SetError($ierr, $iext, 0)
	EndIf
	Return $prtlstub
EndFunc

Func _processdestroyremotethreadstub($hprocess, $pstub)
	Local $vret = _processmemoryfree($hprocess, $pstub)
	Return SetError(@error, @extended, $vret)
EndFunc

Global $_common_ntdll = DllOpen("ntdll.dll")

Func __pudqueryprocess($hprocess, $iprocinfoclass, $vprocinfodata, $iprocinfosz, $sprocinfotype = "ptr")
	Local $aret = DllCall($_common_ntdll, "long", "NtQueryInformationProcess", "handle", $hprocess, "int", $iprocinfoclass, $sprocinfotype, $vprocinfodata, "ulong", $iprocinfosz, "ulong*", 0)
	If @error Then Return SetError(2, @error, "")
	If $aret[0] Then Return SetError(6, $aret[0], "")
	If $aret[5] <> $iprocinfosz Then SetError(7, 0)
	Return $aret
EndFunc

Func __pudgetbasic($hprocess, $iinfo)
	If NOT IsPtr($hprocess) Then Return SetError(1, 0, -1)
	Local $stpbi = DllStructCreate("ulong_ptr;ptr;ulong_ptr;ulong_ptr;ulong_ptr;ulong_ptr")
	__pudqueryprocess($hprocess, 0, DllStructGetPtr($stpbi), DllStructGetSize($stpbi))
	If @error Then Return SetError(@error, @extended, -1)
	Return DllStructGetData($stpbi, $iinfo)
EndFunc

Func _processudgetpid($hprocess)
	Local $vret = __pudgetbasic($hprocess, 5)
	If @error Then Return SetError(@error, @extended, 0)
	Return $vret
EndFunc

Func _processudgetparentpid($hprocess)
	Local $vret = __pudgetbasic($hprocess, 6)
	If @error Then Return SetError(@error, @extended, 0)
	Return $vret
EndFunc

Func _processudgetsessionid($hprocess)
	If NOT IsPtr($hprocess) Then Return SetError(1, 0, -1)
	Local $aret = __pudqueryprocess($hprocess, 24, 0, 4, "ulong*")
	If @error Then Return SetError(@error, @extended, -1)
	Return $aret[3]
EndFunc

Func _processudgethandlecount($hprocess)
	If NOT IsPtr($hprocess) Then Return SetError(1, 0, -1)
	Local $aret = __pudqueryprocess($hprocess, 20, 0, 4, "ulong*")
	If @error Then Return SetError(@error, @extended, -1)
	Return $aret[3]
EndFunc

Func _processudgetmeminfo($hprocess, $icountertoget = -1)
	If NOT IsPtr($hprocess) OR $icountertoget > 10 Then Return SetError(1, 0, -1)
	Local $stvmcounters = DllStructCreate("ulong_ptr;ulong_ptr;dword;ulong_ptr;ulong_ptr;ulong_ptr;ulong_ptr;ulong_ptr;ulong_ptr;ulong_ptr;ulong_ptr")
	__pudqueryprocess($hprocess, 3, DllStructGetPtr($stvmcounters), DllStructGetSize($stvmcounters))
	If @error Then Return SetError(@error, @extended, -1)
	If $icountertoget < 0 Then
		Dim $ameminfo[11]
		For $i = 0 To 8
			$ameminfo[$i] = DllStructGetData($stvmcounters, $i + 3)
		Next
		$ameminfo[9] = DllStructGetData($stvmcounters, 1)
		$ameminfo[10] = DllStructGetData($stvmcounters, 2)
		Return $ameminfo
	EndIf
	If $icountertoget > 8 Then Return DllStructGetData($stvmcounters, $icountertoget - 8)
	Return DllStructGetData($stvmcounters, $icountertoget + 3)
EndFunc

Func _processudgetstrings($hprocess, $bgetenvstr = False)
	Local $ppeb, $stpebtop, $pprocessparams, $stprocessparams
	$ppeb = __pudgetbasic($hprocess, 2)
	If @error Then Return SetError(@error, @extended, "")
	$stpebtop = DllStructCreate("byte;byte;byte;byte;handle;ptr;ptr;ptr")
	_processmemoryread($hprocess, $ppeb, DllStructGetPtr($stpebtop), DllStructGetSize($stpebtop))
	If @error Then Return SetError(@error, @extended, "")
	$pprocessparams = DllStructGetData($stpebtop, 8)
	$stprocessparams = DllStructCreate("ulong;ulong;ulong;ulong;ptr;ulong;ptr;ptr;ptr;ushort;ushort;ptr;ptr;ushort;ushort;ptr;ushort;ushort;ptr;ushort;ushort;ptr;ptr;ulong;ulong;ulong;ulong;ulong;ulong;ulong;ulong;ulong_ptr;ushort;ushort;ptr;ushort;ushort;ptr;ushort;ushort;ptr;ushort;ushort;ptr")
	_processmemoryread($hprocess, $pprocessparams, DllStructGetPtr($stprocessparams), DllStructGetSize($stprocessparams))
	If @error Then Return SetError(@error, @extended, "")
	Local $ainfoarray[9], $aindexes[8] = [10, 14, 17, 20, 33, 36, 39, 42]
	Local $icurminlen, $icurmaxlen, $itemp, $pstring, $ststring, $ierrtotal = 0
	For $i = 0 To 7
		$itemp = $aindexes[$i]
		$icurminlen = DllStructGetData($stprocessparams, $itemp)
		$icurmaxlen = DllStructGetData($stprocessparams, $itemp + 1)
		$pstring = DllStructGetData($stprocessparams, $itemp + 2)
		If $icurminlen > 0 AND $icurmaxlen > 2 Then
			$ststring = DllStructCreate("wchar[" & Int($icurmaxlen / 2) & "]")
			_processmemoryread($hprocess, $pstring, DllStructGetPtr($ststring), $icurmaxlen)
			If @error Then
				$ierrtotal += 1
			Else
				$ainfoarray[$i] = DllStructGetData($ststring, 1)
			EndIf
		EndIf
	Next
	$ainfoarray[2] = StringReplace($ainfoarray[2], "\??\", "", 0, 2)
	If NOT $bgetenvstr Then
		ReDim $ainfoarray[8]
		Return SetExtended($ierrtotal, $ainfoarray)
	EndIf
	Local $stenv, $senvvars, $icutoff, $aenvvars
	$stenv = DllStructCreate("byte[4096]")
	_processmemoryread($hprocess, DllStructGetData($stprocessparams, 23), DllStructGetPtr($stenv), DllStructGetSize($stenv))
	If @error Then $ierrtotal += 1
	$senvvars = BinaryToString(DllStructGetData($stenv, 1), 2)
	$icutoff = StringInStr($senvvars, ChrW(0) & ChrW(0), 0)
	If $icutoff Then $senvvars = StringLeft($senvvars, $icutoff - 1)
	$ainfoarray[8] = StringReplace($senvvars, ChrW(0), @LF)
	Return SetExtended($ierrtotal, $ainfoarray)
EndFunc

Func _processudgetheaps($hprocess)
	Local $ppeb, $iheapoffset, $stheapinfo, $stheaps, $iheaps
	$ppeb = __pudgetbasic($hprocess, 2)
	If @error Then Return SetError(@error, @extended, "")
	If @AutoItX64 Then
		$iheapoffset = 232
	Else
		$iheapoffset = 136
	EndIf
	$stheapinfo = DllStructCreate("ulong;ulong;ptr")
	_processmemoryread($hprocess, $ppeb + $iheapoffset, DllStructGetPtr($stheapinfo), DllStructGetSize($stheapinfo))
	If @error Then Return SetError(@error, @extended, "")
	$iheaps = DllStructGetData($stheapinfo, 1)
	If $iheaps = 0 Then Return SetError(8, 0, "")
	$stheaps = DllStructCreate("ptr[" & $iheaps & "]")
	_processmemoryread($hprocess, DllStructGetData($stheapinfo, 3), DllStructGetPtr($stheaps), DllStructGetSize($stheaps))
	If @error Then Return SetError(@error, @extended, "")
	Dim $aheaps[$iheaps]
	For $i = 0 To $iheaps - 1
		$aheaps[$i] = DllStructGetData($stheaps, 1, $i + 1)
	Next
	Return SetExtended($iheaps, $aheaps)
EndFunc

Func _processudgetsubsysteminfo($hprocess)
	Local $ppeb, $isubsysoffset, $stsubsysinfo
	$ppeb = __pudgetbasic($hprocess, 2)
	If @error Then Return SetError(@error, @extended, -1)
	If @AutoItX64 Then
		$isubsysoffset = 296
	Else
		$isubsysoffset = 180
	EndIf
	$stsubsysinfo = DllStructCreate("ulong")
	_processmemoryread($hprocess, $ppeb + $isubsysoffset, DllStructGetPtr($stsubsysinfo), 4)
	If @error Then Return SetError(@error, @extended, -1)
	Return DllStructGetData($stsubsysinfo, 1)
EndFunc

Func _processudsuspend($hprocess)
	If NOT IsPtr($hprocess) Then Return SetError(1, 0, False)
	Local $aret = DllCall($_common_ntdll, "long", "NtSuspendProcess", "handle", $hprocess)
	If @error Then Return SetError(2, @error, False)
	If $aret[0] Then Return SetError(6, $aret[0], False)
	Return True
EndFunc

Func _processudresume($hprocess)
	If NOT IsPtr($hprocess) Then Return SetError(1, 0, False)
	Local $aret = DllCall($_common_ntdll, "long", "NtResumeProcess", "handle", $hprocess)
	If @error Then Return SetError(2, @error, False)
	If $aret[0] Then Return SetError(6, $aret[0], False)
	Return True
EndFunc

If StringRegExp(@OSVersion, "_(XP|200(0|3))") Then
	Dim $thread_query_limited_info = 64
	Dim $thread_set_limited_info = 32
Else
	Dim $thread_query_limited_info = 2048
	Dim $thread_set_limited_info = 1024
EndIf
Global Const $_thread_still_active = 259
Global Const $_thread_default_stack_size = 262144
Global $thread_last_exit_code = 0, $thread_last_tid = 0
Global $thread_this_handle = Ptr(-2)

Func _threadopen($ithreadid, $iaccess, $binherithandle = False)
	Local $aret
	If $ithreadid = -1 Then
		$aret = DllCall($_common_kernel32dll, "handle", "GetCurrentThread")
	Else
		$aret = DllCall($_common_kernel32dll, "handle", "OpenThread", "dword", $iaccess, "bool", $binherithandle, "dword", $ithreadid)
	EndIf
	If @error Then Return SetError(2, @error, 0)
	If NOT $aret[0] Then Return SetError(3, 0, 0)
	Return $aret[0]
EndFunc

Func _threadgetcurrentid()
	Local $aret = DllCall($_common_kernel32dll, "dword", "GetCurrentThreadId")
	If @error Then Return SetError(2, @error, 0)
	If NOT $aret[0] Then Return SetError(3, @error, 0)
	Return $aret[0]
EndFunc

Func _threadcreate($pfuncptr, $vparam = 0, $bcreatesuspended = False, $istacksize = 0)
	If NOT IsPtr($pfuncptr) Then Return SetError(1, 0, 0)
	Local $iattrib
	If $bcreatesuspended Then
		$iattrib = 4
	Else
		$iattrib = 0
	EndIf
	If $istacksize AND $istacksize < 2048 Then $istacksize = $_thread_default_stack_size
	Local $aret = DllCall($_common_kernel32dll, "handle", "CreateThread", "ptr", 0, "ulong_ptr", $istacksize, "ptr", $pfuncptr, "ulong_ptr", $vparam, "dword", $iattrib, "dword*", 0)
	If @error Then Return SetError(2, @error, 0)
	If NOT $aret[0] Then Return SetError(3, 0, 0)
	$thread_last_tid = $aret[6]
	Return SetError(0, $aret[6], $aret[0])
EndFunc

Func _threadgetprocessid($hthread)
	If NOT IsPtr($hthread) Then Return SetError(1, 0, 0)
	Local $aret = DllCall($_common_kernel32dll, "dword", "GetProcessIdOfThread", "handle", $hthread)
	If @error Then Return SetError(2, @error, 0)
	If NOT $aret[0] Then Return SetError(3, 0, 0)
	Return $aret[0]
EndFunc

Func _threadgetthreadid($hthread)
	If NOT IsPtr($hthread) Then Return SetError(1, 0, 0)
	Local $aret = DllCall($_common_kernel32dll, "dword", "GetThreadId", "handle", $hthread)
	If @error Then Return SetError(2, @error, 0)
	If NOT $aret[0] Then Return SetError(3, 0, 0)
	Return $aret[0]
EndFunc

Func _threadgetpriority($hthread)
	If NOT IsPtr($hthread) Then Return SetError(1, 0, -1)
	Local $aret = DllCall($_common_kernel32dll, "int", "GetThreadPriority", "handle", $hthread)
	If @error Then Return SetError(2, @error, -1)
	If $aret[0] = 2147483647 Then Return SetError(3, 0, -1)
	Return $aret[0]
EndFunc

Func _threadsetpriority($hthread, $ipriority = 0)
	If NOT IsPtr($hthread) Then Return SetError(1, 0, False)
	Local $aret = DllCall($_common_kernel32dll, "bool", "SetThreadPriority", "handle", $hthread, "int", $ipriority)
	If @error Then Return SetError(2, @error, False)
	If NOT $aret[0] Then Return SetError(3, 0, False)
	Return True
EndFunc

Func _threadgetaffinitymask($hthread, $itempaffinitymask = 1)
	If $itempaffinitymask = 0 Then Return SetError(1, 0, 0)
	_threadsetaffinitymask($hthread, $itempaffinitymask)
	If @error Then Return SetError(@error, @extended, 0)
	Local $iprevaffinity = @extended
	_threadsetaffinitymask($hthread, $iprevaffinity)
	Return $iprevaffinity
EndFunc

Func _threadsetaffinitymask($hthread, $iaffinitymask)
	If NOT IsPtr($hthread) OR $iaffinitymask = 0 Then Return SetError(1, 0, False)
	Local $aret = DllCall($_common_kernel32dll, "dword_ptr", "SetThreadAffinityMask", "handle", $hthread, "dword_ptr", $iaffinitymask)
	If @error Then Return SetError(2, @error, False)
	If $aret[0] = 0 Then Return SetError(3, 0, False)
	Return SetExtended($aret[0], True)
EndFunc

Func _threadgettimes($hthread, $itimetoget = -1)
	If NOT IsPtr($hthread) OR $itimetoget > 3 Then Return SetError(1, 0, -1)
	Local $aret = DllCall($_common_kernel32dll, "bool", "GetThreadTimes", "handle", $hthread, "uint64*", 0, "uint64*", 0, "uint64*", 0, "uint64*", 0)
	If @error Then Return SetError(2, @error, -1)
	If NOT $aret[0] Then Return SetError(3, 0, -1)
	If $itimetoget < 0 Then
		Dim $atimes[4] = [$aret[2], $aret[3], $aret[4], $aret[5]]
		Return $atimes
	EndIf
	Return $aret[$itimetoget + 2]
EndFunc

Func _threadwaitforexit($hthread, $itimeout = -1)
	If NOT IsPtr($hthread) OR $itimeout < -1 Then Return SetError(1, 0, -1)
	Local $aret, $itimer
	$itimer = TimerInit()
	While 1
		$aret = DllCall($_common_kernel32dll, "dword", "WaitForSingleObject", "handle", $hthread, "dword", 0)
		If @error Then Return SetError(2, @error, False)
		If $aret[0] = 0 Then Return True
		If $aret[0] AND $aret[0] <> 258 Then Return SetError(4, $aret[0], False)
		If $itimeout > -1 AND TimerDiff($itimer) > $itimeout Then Return SetError(16, 0, False)
		Sleep(10)
	WEnd
EndFunc

Func _threadstillactive($hthread)
	Local $bret = _threadwaitforexit($hthread, 0)
	If @error = 16 Then Return SetError(0, 16, True)
	Return SetError(@error, @extended, NOT $bret)
EndFunc

Func _threadgetexitcode($hthread)
	If NOT IsPtr($hthread) Then Return SetError(1, 0, -1)
	Local $aret = DllCall($_common_kernel32dll, "bool", "GetExitCodeThread", "handle", $hthread, "int*", 0)
	If @error Then Return SetError(2, @error, -1)
	If NOT $aret[0] Then Return SetError(3, 0, -1)
	$thread_last_exit_code = $aret[2]
	Return $aret[2]
EndFunc

Func _threadsuspend($hthread)
	If NOT IsPtr($hthread) Then Return SetError(1, 0, False)
	Local $aret = DllCall($_common_kernel32dll, "int", "SuspendThread", "handle", $hthread)
	If @error Then Return SetError(2, @error, False)
	If $aret[0] = -1 Then Return SetError(3, 0, False)
	Return True
EndFunc

Func _threadwow64suspend($hthread)
	If NOT IsPtr($hthread) Then Return SetError(1, 0, False)
	Local $aret = DllCall($_common_kernel32dll, "int", "Wow64SuspendThread", "handle", $hthread)
	If @error Then Return SetError(2, @error, False)
	If $aret[0] = -1 Then Return SetError(3, 0, False)
	Return True
EndFunc

Func _threadresume($hthread)
	If NOT IsPtr($hthread) Then Return SetError(1, 0, False)
	Local $aret = DllCall($_common_kernel32dll, "int", "ResumeThread", "handle", $hthread)
	If @error Then Return SetError(2, @error, False)
	If $aret[0] = -1 Then Return SetError(3, 0, False)
	Return True
EndFunc

Func _threadterminate($hthread, $iexitcode = 0)
	If NOT IsPtr($hthread) Then Return SetError(1, 0, False)
	Local $aret = DllCall($_common_kernel32dll, "bool", "TerminateThread", "handle", $hthread, "int", $iexitcode)
	If @error Then Return SetError(2, @error, False)
	If NOT $aret[0] Then Return SetError(3, 0, False)
	Return True
EndFunc

Func _threadclosehandle(ByRef $hthread)
	If NOT IsPtr($hthread) Then Return SetError(1, 0, False)
	Local $aret = DllCall($_common_kernel32dll, "bool", "CloseHandle", "handle", $hthread)
	If @error Then Return SetError(2, @error, False)
	If NOT $aret[0] Then Return SetError(3, 0, False)
	$hthread = 0
	Return True
EndFunc

Func _threadgetwinthreadid($hwnd, $vuser32dll = "user32.dll")
	If NOT IsHWnd($hwnd) OR $vuser32dll < 0 Then Return SetError(1, 0, 0)
	Local $aret = DllCall($vuser32dll, "dword", "GetWindowThreadProcessId", "hwnd", $hwnd, "dword*", 0)
	If @error Then Return SetError(2, @error, 0)
	If $aret[0] = 0 Then Return SetError(3, 0, 0)
	Return SetExtended($aret[2], $aret[0])
EndFunc

Global $remote_thread_last_method = 0, $remote_thread_last_tid = 0

Func _processcreateremotethread($hprocess, $pcodeptr, $vparam = 0, $bcreatesuspended = False, $iundocumented = 0, $bwow64code = False)
	If NOT IsPtr($hprocess) OR NOT IsPtr($pcodeptr) Then Return SetError(1, 0, 0)
	Local $iattrib, $aret, $stclientid
	If _processudgetsubsysteminfo($hprocess) = 1 Then Return SetError(-11, 0, 0)
	If @AutoItX64 Then
		If _processis32bit($hprocess) Then
			If NOT $bwow64code Then Return SetError(6432, 0, 0)
		Else
			If $bwow64code Then Return SetError(3264, 0, 0)
		EndIf
	Else
		If _processis64bit($hprocess) Then Return SetError(3264, 0, 0)
	EndIf
	If $iundocumented >= 0 Then
		If $bcreatesuspended Then
			$iattrib = 4
		Else
			$iattrib = 0
		EndIf
		$aret = DllCall($_common_kernel32dll, "handle", "CreateRemoteThread", "handle", $hprocess, "ptr", 0, "ulong_ptr", 0, "ptr", $pcodeptr, "ulong_ptr", $vparam, "dword", $iattrib, "dword*", 0)
		If @error Then Return SetError(2, @error, 0)
		ConsoleWrite("CreateRemoteThread return: handle:" & $aret[0] & " Thread ID:" & $aret[7] & @CRLF)
		If $aret[0] Then
			$remote_thread_last_method = 1
			$thread_last_tid = $aret[7]
			$remote_thread_last_tid = $aret[7]
			Return SetExtended($aret[7], $aret[0])
		EndIf
		If $iundocumented = 0 Then Return SetError(3, 0, 0)
	EndIf
	$stclientid = DllStructCreate("ulong_ptr;ulong_ptr")
	$aret = DllCall($_common_ntdll, "long", "RtlCreateUserThread", "handle", $hprocess, "ptr", 0, "bool", $bcreatesuspended, "ulong", 0, "ulong*", 0, "ulong*", 0, "ptr", $pcodeptr, "ulong_ptr", $vparam, "handle*", 0, "ptr", DllStructGetPtr($stclientid))
	If @error Then Return SetError(2, @error, 0)
	If $aret[0] Then Return SetError(6, $aret[0], 0)
	$thread_last_tid = DllStructGetData($stclientid, 2)
	$remote_thread_last_method = -1
	$remote_thread_last_tid = $thread_last_tid
	Return SetExtended($thread_last_tid, $aret[9])
EndFunc

Func _dllinject($vprocessid, $sdllpath)
	If NOT IsString($sdllpath) OR $sdllpath = "" Then Return SetError(1, 0, 0)
	Local $hprocess = 0, $hthread = 0, $pallocatedmem = 0, $ploadlibrary, $hinjecteddll, $ststubandstring, $binstub
	Local $istubsz, $idllpathlen = StringLen($sdllpath) + 1
	If $idllpathlen <= 4 OR StringRight($sdllpath, 4) <> ".dll" Then Return SetError(1, 0, 0)
	$hprocess = _processopen($vprocessid, 1082)
	If @error Then Return SetError(@error, @extended, 0)
	$vprocessid = @extended
	Do
		$ploadlibrary = _processgetprocaddress($vprocessid, "kernel32.dll", "LoadLibraryW")
		If @error Then ExitLoop 
		$istubsz = $stub_x64_size
		$pallocatedmem = _processmemoryalloc($hprocess, $istubsz + $idllpathlen * 2, 4096, 64)
		If @error Then ExitLoop 
		$binstub = _processgeneratethreadstub($hprocess, $vprocessid, $ploadlibrary)
		If @error Then ExitLoop 
		$ststubandstring = DllStructCreate("byte[" & $istubsz & "];wchar[" & $idllpathlen & "]")
		DllStructSetData($ststubandstring, 1, $binstub)
		DllStructSetData($ststubandstring, 2, $sdllpath)
		If NOT _processmemorywrite($hprocess, $pallocatedmem, DllStructGetPtr($ststubandstring), $istubsz + $idllpathlen * 2) Then ExitLoop 
		$hthread = _processcreateremotethread($hprocess, $pallocatedmem, $pallocatedmem + $istubsz, False, 1)
		If @error Then ExitLoop 
		ConsoleWrite("Thread ID:" & @extended & @CRLF)
		_threadwaitforexit($hthread)
		$hinjecteddll = _threadgetexitcode($hthread)
		SetError(0)
	Until 1
	Local $ierr = @error, $iext = @extended
	_threadclosehandle($hthread)
	_processmemoryfree($hprocess, $pallocatedmem)
	_processclosehandle($hprocess)
	If $ierr Then Return SetError($ierr, $iext, 0)
	If $hinjecteddll = 0 Then Return SetError(10, 0, 0)
	If @AutoItX64 Then
		Return 1
	Else
		Return Ptr($hinjecteddll)
	EndIf
EndFunc

Func _dlluninject($vprocessid, $vdllmodule)
	If IsString($vdllmodule) Then
		$vdllmodule = _processgetmodulebaseaddress($vprocessid, $vdllmodule)
		If @error Then Return SetError(@error, @extended, False)
	ElseIf NOT IsPtr($vdllmodule) Then
		Return SetError(1, 0, False)
	EndIf
	Local $hprocess = 0, $hthread = 0, $pfreelibrary, $iexitcode = 0, $premotestub = 0
	$hprocess = _processopen($vprocessid, 1082)
	If @error Then Return SetError(@error, @extended, 0)
	$vprocessid = @extended
	Do
		$pfreelibrary = _processgetprocaddress($vprocessid, "kernel32.dll", "FreeLibrary")
		If @error Then ExitLoop 
		$premotestub = _processcreateremotethreadstub($hprocess, $vprocessid, $pfreelibrary)
		If @error Then ExitLoop 
		$hthread = _processcreateremotethread($hprocess, $premotestub, $vdllmodule, False, 1)
		If @error Then ExitLoop 
		ConsoleWrite("Thread ID:" & @extended & @CRLF)
		_threadwaitforexit($hthread)
		$iexitcode = _threadgetexitcode($hthread)
		SetError(0)
	Until 1
	Local $ierr = @error, $iext = @extended
	_threadclosehandle($hthread)
	_processmemoryfree($hprocess, $premotestub)
	_processclosehandle($hprocess)
	If $ierr Then Return SetError($ierr, $iext, 0)
	If $iexitcode = 0 Then Return SetError(10, 0, False)
	Return SetExtended($iexitcode, True)
EndFunc

Global $_timers_atimerids[1][3]

Func _timer_diff($itimestamp)
	Return 1000 * (__timer_queryperformancecounter()-$itimestamp) / __timer_queryperformancefrequency()
EndFunc

Func _timer_getidletime()
	Local $tstruct = DllStructCreate("uint;dword")
	DllStructSetData($tstruct, 1, DllStructGetSize($tstruct))
	Local $aresult = DllCall("user32.dll", "bool", "GetLastInputInfo", "ptr", DllStructGetPtr($tstruct))
	If @error OR $aresult[0] = 0 Then Return SetError(@error, @extended, 0)
	Local $avticks = DllCall("Kernel32.dll", "dword", "GetTickCount")
	If @error OR NOT $aresult[0] Then Return SetError(@error, @extended, 0)
	Local $idiff = $avticks[0] - DllStructGetData($tstruct, 2)
	If $idiff < 0 Then Return SetExtended(1, $avticks[0])
	Return $idiff
EndFunc

Func _timer_gettimerid($iwparam)
	Local $_itimerid = Dec(Hex($iwparam, 8)), $imax = UBound($_timers_atimerids) - 1
	For $x = 1 To $imax
		If $_itimerid = $_timers_atimerids[$x][1] Then Return $_timers_atimerids[$x][0]
	Next
	Return 0
EndFunc

Func _timer_init()
	Return __timer_queryperformancecounter()
EndFunc

Func _timer_killalltimers($hwnd)
	Local $inumtimers = $_timers_atimerids[0][0]
	If $inumtimers = 0 Then Return False
	Local $aresult, $hcallback = 0
	For $x = $inumtimers To 1 Step -1
		If IsHWnd($hwnd) Then
			$aresult = DllCall("user32.dll", "bool", "KillTimer", "hwnd", $hwnd, "uint_ptr", $_timers_atimerids[$x][1])
		Else
			$aresult = DllCall("user32.dll", "bool", "KillTimer", "hwnd", $hwnd, "uint_ptr", $_timers_atimerids[$x][0])
		EndIf
		If @error OR $aresult[0] = 0 Then Return SetError(@error, @extended, False)
		$hcallback = $_timers_atimerids[$x][2]
		If $hcallback <> 0 Then DllCallbackFree($hcallback)
		$_timers_atimerids[0][0] -= 1
	Next
	ReDim $_timers_atimerids[1][3]
	Return True
EndFunc

Func _timer_killtimer($hwnd, $itimerid)
	Local $aresult[1] = [0], $hcallback = 0, $iubound = UBound($_timers_atimerids) - 1
	For $x = 1 To $iubound
		If $_timers_atimerids[$x][0] = $itimerid Then
			If IsHWnd($hwnd) Then
				$aresult = DllCall("user32.dll", "bool", "KillTimer", "hwnd", $hwnd, "uint_ptr", $_timers_atimerids[$x][1])
			Else
				$aresult = DllCall("user32.dll", "bool", "KillTimer", "hwnd", $hwnd, "uint_ptr", $_timers_atimerids[$x][0])
			EndIf
			If @error OR $aresult[0] = 0 Then Return SetError(@error, @extended, False)
			$hcallback = $_timers_atimerids[$x][2]
			If $hcallback <> 0 Then DllCallbackFree($hcallback)
			For $i = $x To $iubound - 1
				$_timers_atimerids[$i][0] = $_timers_atimerids[$i + 1][0]
				$_timers_atimerids[$i][1] = $_timers_atimerids[$i + 1][1]
				$_timers_atimerids[$i][2] = $_timers_atimerids[$i + 1][2]
			Next
			ReDim $_timers_atimerids[UBound($_timers_atimerids - 1)][3]
			$_timers_atimerids[0][0] -= 1
			ExitLoop 
		EndIf
	Next
	Return $aresult[0] <> 0
EndFunc

Func __timer_queryperformancecounter()
	Local $aresult = DllCall("kernel32.dll", "bool", "QueryPerformanceCounter", "int64*", 0)
	If @error Then Return SetError(@error, @extended, -1)
	Return SetExtended($aresult[0], $aresult[1])
EndFunc

Func __timer_queryperformancefrequency()
	Local $aresult = DllCall("kernel32.dll", "bool", "QueryPerformanceFrequency", "int64*", 0)
	If @error Then Return SetError(@error, @extended, 0)
	Return SetExtended($aresult[0], $aresult[1])
EndFunc

Func _timer_settimer($hwnd, $ielapse = 250, $stimerfunc = "", $itimerid = -1)
	Local $aresult[1] = [0], $ptimerfunc = 0, $hcallback = 0, $iindex = $_timers_atimerids[0][0] + 1
	If $itimerid = -1 Then
		ReDim $_timers_atimerids[$iindex + 1][3]
		$_timers_atimerids[0][0] = $iindex
		$itimerid = $iindex + 1000
		For $x = 1 To $iindex
			If $_timers_atimerids[$x][0] = $itimerid Then
				$itimerid = $itimerid + 1
				$x = 0
			EndIf
		Next
		If $stimerfunc <> "" Then
			$hcallback = DllCallbackRegister($stimerfunc, "none", "hwnd;int;uint_ptr;dword")
			If $hcallback = 0 Then Return SetError(-1, -1, 0)
			$ptimerfunc = DllCallbackGetPtr($hcallback)
			If $ptimerfunc = 0 Then Return SetError(-1, -1, 0)
		EndIf
		$aresult = DllCall("user32.dll", "uint_ptr", "SetTimer", "hwnd", $hwnd, "uint_ptr", $itimerid, "uint", $ielapse, "ptr", $ptimerfunc)
		If @error OR $aresult[0] = 0 Then Return SetError(@error, @extended, 0)
		$_timers_atimerids[$iindex][0] = $aresult[0]
		$_timers_atimerids[$iindex][1] = $itimerid
		$_timers_atimerids[$iindex][2] = $hcallback
	Else
		For $x = 1 To $iindex - 1
			If $_timers_atimerids[$x][0] = $itimerid Then
				If IsHWnd($hwnd) Then $itimerid = $_timers_atimerids[$x][1]
				$hcallback = $_timers_atimerids[$x][2]
				If $hcallback <> 0 Then
					$ptimerfunc = DllCallbackGetPtr($hcallback)
					If $ptimerfunc = 0 Then Return SetError(-1, -1, 0)
				EndIf
				$aresult = DllCall("user32.dll", "uint_ptr", "SetTimer", "hwnd", $hwnd, "uint_ptr", $itimerid, "int", $ielapse, "ptr", $ptimerfunc)
				If @error OR $aresult[0] = 0 Then Return SetError(@error, @extended, 0)
				ExitLoop 
			EndIf
		Next
	EndIf
	Return $aresult[0]
 EndFunc
 
 ;pt 5*******************************
 