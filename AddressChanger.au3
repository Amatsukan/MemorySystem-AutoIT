

Func _change()
	$0x = "0x"
	$process = GUICtrlRead($inputa)
	$adress1 = GUICtrlRead($inputb)
	$adress2 = GUICtrlRead($inputc)
	$adress3 = GUICtrlRead($inputd)
	$adress4 = GUICtrlRead($inpute)
	$adress5 = GUICtrlRead($inputf)
	$value1 = GUICtrlRead($inputg)
	$value2 = GUICtrlRead($inputh)
	$value3 = GUICtrlRead($inputi)
	$value4 = GUICtrlRead($inputj)
	$value5 = GUICtrlRead($inputk)
	$type = GUICtrlRead($comboa)
	$pid = ProcessWait($processs)
	$open = _memoryopen($pid)
	If NOT $adress1 = "" Then
		If $type = "4Bytes" Then
			_memorywrite($0x & $adress1, $open, $value1, "long")
		EndIf
		If $type = "Float" Then
			_memorywrite($0x & $adress1, $open, $value1, "float")
		EndIf
		If $type = "Double" Then
			_memorywrite($0x & $adress1, $open, $value1, "double")
		EndIf
	EndIf
	If NOT $adress2 = "" Then
		If $type = "4Bytes" Then
			_memorywrite($0x & $adress2, $open, $value2, "long")
		EndIf
		If $type = "Float" Then
			_memorywrite($0x & $adress2, $open, $value2, "float")
		EndIf
		If $type = "Double" Then
			_memorywrite($0x & $adress2, $open, $value2, "double")
		EndIf
	EndIf
	If NOT $adress3 = "" Then
		If $type = "4Bytes" Then
			_memorywrite($0x & $adress3, $open, $value3, "long")
		EndIf
		If $type = "Float" Then
			_memorywrite($0x & $adress3, $open, $value3, "float")
		EndIf
		If $type = "Double" Then
			_memorywrite($0x & $adress3, $open, $value3, "double")
		EndIf
	EndIf
	If NOT $adress4 = "" Then
		If $type = "4Bytes" Then
			_memorywrite($0x & $adress4, $open, $value4, "long")
		EndIf
		If $type = "Float" Then
			_memorywrite($0x & $adress4, $open, $value4, "float")
		EndIf
		If $type = "Double" Then
			_memorywrite($0x & $adress4, $open, $value4, "double")
		EndIf
	EndIf
	If NOT $adress5 = "" Then
		If $type = "4Bytes" Then
			_memorywrite($0x & $adress5, $open, $value5, "long")
		EndIf
		If $type = "Float" Then
			_memorywrite($0x & $adress5, $open, $value5, "float")
		EndIf
		If $type = "Double" Then
			_memorywrite($0x & $adress5, $open, $value5, "double")
		EndIf
	EndIf
	_memoryclose($open)
EndFunc

Func _ver()
	$0x = "0x"
	$process = GUICtrlRead($inputa)
	$adress1 = GUICtrlRead($inputb)
	$adress2 = GUICtrlRead($inputc)
	$adress3 = GUICtrlRead($inputd)
	$adress4 = GUICtrlRead($inpute)
	$adress5 = GUICtrlRead($inputf)
	$value1 = GUICtrlRead($inputg)
	$value2 = GUICtrlRead($inputh)
	$value3 = GUICtrlRead($inputi)
	$value4 = GUICtrlRead($inputj)
	$value5 = GUICtrlRead($inputk)
	$type = GUICtrlRead($comboa)
	$pid = ProcessWait($processs)
	$open = _memoryopen($pid)
	If NOT $adress1 = "" Then
		If $type = "4Bytes" Then
			$valuex1 = _memoryread($0x & $adress1, $open, "long")
			MsgBox(0, "Value do adress: " & $adress1, $valuex1)
		EndIf
		If $type = "Float" Then
			$valuex2 = _memoryread($0x & $adress1, $open, "float")
			MsgBox(0, "Value do adress: " & $adress1, $valuex2)
		EndIf
		If $type = "Double" Then
			$valuex3 = _memoryread($0x & $adress1, $open, "double")
			MsgBox(0, "Value do adress: " & $adress1, $valuex3)
		EndIf
	EndIf
	If NOT $adress2 = "" Then
		If $type = "4Bytes" Then
			$valuex4 = _memoryread($0x & $adress2, $open, "long")
			MsgBox(0, "Value do adress: " & $adress2, $valuex4)
		EndIf
		If $type = "Float" Then
			$valuex5 = _memoryread($0x & $adress2, $open, "float")
			MsgBox(0, "Value do adress: " & $adress2, $valuex5)
		EndIf
		If $type = "Double" Then
			$valuex6 = _memoryread($0x & $adress2, $open, "double")
			MsgBox(0, "Value do adress: " & $adress2, $valuex6)
		EndIf
	EndIf
	If NOT $adress3 = "" Then
		If $type = "4Bytes" Then
			$valuex7 = _memoryread($0x & $adress3, $open, "long")
			MsgBox(0, "Value do adress: " & $adress3, $valuex7)
		EndIf
		If $type = "Float" Then
			$valuex8 = _memoryread($0x & $adress3, $open, "float")
			MsgBox(0, "Value do adress: " & $adress3, $valuex8)
		EndIf
		If $type = "Double" Then
			$valuex9 = _memoryread($0x & $adress3, $open, "double")
			MsgBox(0, "Value do adress: " & $adress3, $valuex9)
		EndIf
	EndIf
	If NOT $adress4 = "" Then
		If $type = "4Bytes" Then
			$valuex10 = _memoryread($0x & $adress4, $open, "long")
			MsgBox(0, "Value do adress: " & $adress4, $valuex10)
		EndIf
		If $type = "Float" Then
			$valuex11 = _memoryread($0x & $adress4, $open, "float")
			MsgBox(0, "Value do adress: " & $adress4, $valuex11)
		EndIf
		If $type = "Double" Then
			$valuex12 = _memoryread($0x & $adress4, $open, "double")
			MsgBox(0, "Value do adress: " & $adress4, $valuex12)
		EndIf
	EndIf
	If NOT $adress5 = "" Then
		If $type = "4Bytes" Then
			$valuex13 = _memoryread($0x & $adress5, $open, "long")
			MsgBox(0, "Value do adress: " & $adress5, $valuex13)
		EndIf
		If $type = "Float" Then
			$valuex14 = _memoryread($0x & $adress5, $open, "float")
			MsgBox(0, "Value do adress: " & $adress5, $valuex14)
		EndIf
		If $type = "Double" Then
			$valuex15 = _memoryread($0x & $adress5, $open, "double")
			MsgBox(0, "Value do adress: " & $adress5, $valuex15)
		EndIf
	EndIf
	_memoryclose($open)
EndFunc

#Region ### Funcoes Internas ###

Func _memoryopen($iv_pid, $iv_desiredaccess = 2035711, $iv_inherithandle = 1)
	If NOT ProcessExists($iv_pid) Then
		SetError(1)
		Return 0
	EndIf
	Local $ah_handle[2] = [DllOpen("kernel32.dll")]
	If @error Then
		SetError(2)
		Return 0
	EndIf
	Local $av_openprocess = DllCall($ah_handle[0], "int", "OpenProcess", "int", $iv_desiredaccess, "int", $iv_inherithandle, "int", $iv_pid)
	If @error Then
		DllClose($ah_handle[0])
		SetError(3)
		Return 0
	EndIf
	$ah_handle[1] = $av_openprocess[0]
	Return $ah_handle
EndFunc

Func _memorywrite($iv_address, $ah_handle, $v_data, $sv_type = "dword")
	If NOT IsArray($ah_handle) Then
		SetError(1)
		Return 0
	EndIf
	Local $v_buffer = DllStructCreate($sv_type)
	If @error Then
		SetError(@error + 1)
		Return 0
	Else
		DllStructSetData($v_buffer, 1, $v_data)
		If @error Then
			SetError(6)
			Return 0
		EndIf
	EndIf
	DllCall($ah_handle[0], "int", "WriteProcessMemory", "int", $ah_handle[1], "int", $iv_address, "ptr", DllStructGetPtr($v_buffer), "int", DllStructGetSize($v_buffer), "int", "")
	If NOT @error Then
		Return 1
	Else
		SetError(7)
		Return 0
	EndIf
EndFunc

Func _memoryclose($ah_handle)
	If NOT IsArray($ah_handle) Then
		SetError(1)
		Return 0
	EndIf
	DllCall($ah_handle[0], "int", "CloseHandle", "int", $ah_handle[1])
	If NOT @error Then
		DllClose($ah_handle[0])
		Return 1
	Else
		DllClose($ah_handle[0])
		SetError(2)
		Return 0
	EndIf
EndFunc

Func _memoryread($iv_address, $ah_handle, $sv_type = "dword")
	If NOT IsArray($ah_handle) Then
		SetError(1)
		Return 0
	EndIf
	Local $v_buffer = DllStructCreate($sv_type)
	If @error Then
		SetError(@error + 1)
		Return 0
	EndIf
	DllCall($ah_handle[0], "int", "ReadProcessMemory", "int", $ah_handle[1], "int", $iv_address, "ptr", DllStructGetPtr($v_buffer), "int", DllStructGetSize($v_buffer), "int", "")
	If NOT @error Then
		Local $v_value = DllStructGetData($v_buffer, 1)
		Return $v_value
	Else
		SetError(6)
		Return 0
	EndIf
EndFunc
