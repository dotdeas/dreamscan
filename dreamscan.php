<?php
	// os check and console clear
	$uname=php_uname();
	if(preg_match("/Linux/",$uname)) {
		$colorsupport=true;
		system("clear");
	} elseif(preg_match("/Darwin/",$uname)) {
		$colorsupport=true;
		system("clear");
	} else {
		$colorsupport=false;
		system("cls");
	}

	