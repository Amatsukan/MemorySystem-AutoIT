Func _changename()
	#Region ### START Koda GUI section ### Form=
	$amatsukans = InputBox("Trocando", "Escolha o novo nome para a sua janela.")
	WinSetTitle("With Your Destiny", "", $amatsukans)
	#EndRegion ### END Koda GUI section ###
EndFunc