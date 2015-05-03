
Func _autosuspend()
	If $autosuspend = True Then
		If ProcessExists(GUICtrlRead($input1)) Then
			_suspend()
			$autosuspend = False
			GUICtrlSetState($checkbox2, $gui_unchecked)
		EndIf
	EndIf
EndFunc

Func _autoinject()
	If $autoinject = True Then
		If ProcessExists(GUICtrlRead($input1)) Then
			_injection()
			$autoinject = False
			GUICtrlSetState($checkbox1, $gui_unchecked)
		EndIf
	EndIf
EndFunc

Func _lista()
	GUICtrlSetData($list1, "")
	$processlist = ProcessList()
	For $listar = 1 To $processlist[0][0]
		GUICtrlSetData($list1, $processlist[$listar][0])
	Next
EndFunc

Func _pid($processname)
	$pid = ProcessExists($processname)
	If GUICtrlRead($label1) <> " " & $pid Then GUICtrlSetData($label1, " " & $pid)
EndFunc

Func _localdll()
	$local = FileOpenDialog($janela, @DesktopDir, "DLL (*.dll)", 5)
	If NOT @error Then
	EndIf
EndFunc

Func _injection()
	GUICtrlSetData($label2, "Ready")
	$local = StringReplace($local, "|", "|")
	If @extended = 0 Then
		GUICtrlSetData($label2, "Injecting ...")
		_dllinject(GUICtrlRead($input1), $local)
		If NOT @error Then
			MsgBox(64, $janela, "Injetado com Sucesso")
			GUICtrlSetData($label2, "Injetado")
		Else
			GUICtrlSetData($label2, "Falhou ...")
		EndIf
	Else
		$local = StringSplit($local, "|")
		For $arquivos = 2 To $local[0]
			_dllinject(GUICtrlRead($input1), $local[1] & "\" & $local[$arquivos])
			GUICtrlSetData($label2, "Injetando ...")
		Next
		MsgBox(64, $janela, "Injetado com Sucesso")
		GUICtrlSetData($label2, "Injetado")
	EndIf
EndFunc

Func _suspend()
	$hprocess = _processopen(GUICtrlRead($input1), 2048)
	_processudsuspend($hprocess)
	GUICtrlSetData($label2, "Processo Suspendido")
EndFunc

Func _resume()
	$hprocess = _processopen(GUICtrlRead($input1), 2048)
	_processudresume($hprocess)
	GUICtrlSetData($label2, "Process Continuado")
EndFunc
