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

	// settings
	set_time_limit(0);
	mb_internal_encoding("utf-8");
	date_default_timezone_set("Europe/London");
	ini_set("memory_limit","256M");
	ini_set("max_execution_time",0);
	ini_set("log_errors",0);
	ini_set("html_errors",0);

	// functions
	function app_consolewrite($string,$timestamp=false,$type="out") {
		if($timestamp) {
			$dtstamp=textcolor("yellow","[".date("Y-m-d H:i:s")."]");
		} else {
			$dtstamp="";
		}
		if($type=="out") {
			fwrite(STDOUT,$dtstamp.$string.PHP_EOL);
		} elseif($type=="error") {
			fwrite(STDERR,$dtstamp.$string.PHP_EOL);
		}
	}

	function app_textcolor($fgcolor,$string,$bgcolor=null) {
		global $colorsupport;
		$resetcolor="\033[0m";
		$foreground_colors=array(
			"black"=>"\033[0;30m",
			"dark_gray"=>"\033[1;30m",
			"light_gray"=>"\033[0;37m",
			"white"=>"\033[1;37m",
			"blue"=>"\033[0;34m",
			"light_blue"=>"\033[1;34m",
			"cyan"=>"\033[0;36m",
			"light_cyan"=>"\033[1;36m",
			"green"=>"\033[0;32m",
			"light_green"=>"\033[1;32m",
			"red"=>"\033[0;31m",
			"light_red"=>"\033[1;31m",
			"orange"=>"\033[38;5;208m",
			"purple"=>"\033[0;35m",
			"light_purple"=>"\033[1;35m",
			"brown"=>"\033[0;33m",
			"yellow"=>"\033[1;33m"
		);
		$background_colors=array(
			"black"=>"\033[40m",
			"red"=>"\033[41m",
			"green"=>"\033[42m",
			"yellow"=>"\033[43m",
			"blue"=>"\033[44m",
			"magenta"=>"\033[45m",
			"cyan"=>"\033[46m",
			"light_cyan"=>"\033[47m"
		);
		if($colorsupport) {
			$data="";
				if(isset($fgcolor) && array_key_exists($fgcolor,$foreground_colors)) {
					$data.=$foreground_colors[$fgcolor];
				}
				if(isset($bgcolor) && array_key_exists($bgcolor,$background_colors)) {
					$data.=$background_colors[$bgcolor];
				}
			return($data.$string.$resetcolor);
		} else {
			return($string);
		}
	}

	function app_checkcli() {
		if(php_sapi_name()!="cli") {
			die(app_consolewrite(app_textcolor("white","dreamscan must be run as a cli application","red"),false,"error"));
		}
	}

	function app_checkdep() {
		if(!extension_loaded("curl")) {
			die(app_consolewrite(app_textcolor("white","curl not found, please install curl","red"),false,"error"));
		}
	}

	function app_header() {
	    app_consolewrite(app_textcolor("red","    __                                                   "));
	    app_consolewrite(app_textcolor("orange",".--|  |.----.-----.---.-.--------.-----.----.---.-.-----."));
	    app_consolewrite(app_textcolor("yellow","|  _  ||   _|  -__|  _  |        |__ --|  __|  _  |     |"));
	    app_consolewrite(app_textcolor("green","|_____||__| |_____|___._|__|__|__|_____|____|___._|__|__|"));
	    app_consolewrite(null);
	    app_consolewrite(app_textcolor("yellow","                  [ code by deas / version 0.0.0 ]"));
	    app_consolewrite(null);
	}

	function app_help() {
		app_consolewrite(app_textcolor("blue","usage: php dreamscan.php [options] ..."));
		app_consolewrite(null);
		app_consolewrite(app_textcolor("blue","  -h    print this help"));
		app_consolewrite(app_textcolor("blue","  -t    scan type (range or file)"));
		app_consolewrite(app_textcolor("blue","  -s    start ip for range scan"));
		app_consolewrite(app_textcolor("blue","  -e    end ip for range scan"));
		app_consolewrite(app_textcolor("blue","  -f    ip file for file scan"));
		app_consolewrite(app_textcolor("blue","  -o    output file"));
		app_consolewrite(null);
	}

	function app_run() {
		$options="t:s:e:f:o:h::";
		$opts=getopt($options);
			if(isset($opts["h"])) {
				app_help();
				exit;
			}
			if(isset($opts["t"]) && $opts["t"]<>"") {
				if($opts["t"]=="range") {
					if(isset($opts["s"]) && isset($opts["e"]) && !empty($opts["s"]) && !empty($opts["e"])) {
						$iprange=scan_geniprange($opts["s"],$opts["e"]);
					} else {
						die(app_consolewrite(app_textcolor("red","start and end range not defined"),false,"error"));
					}
				} elseif($opts["t"]=="file") {
					if(isset($opts["f"]) && !empty($opts["f"])) {
						if(file_exists($opts["f"])) {
							$iprange=file($opts["f"],FILE_IGNORE_NEW_LINES|FILE_SKIP_EMPTY_LINES);
						} else {
							die(app_consolewrite(app_textcolor("red","ip file not found"),false,"error"));
						}
					} else {
						die(app_consolewrite(app_textcolor("red","no ip file defined"),false,"error"));
					}
				} else {
					die(app_consolewrite(app_textcolor("red","unsupported scan type"),false,"error"));
				}
			} else {
				die(app_consolewrite(app_textcolor("red","no scan type defined"),false,"error"));
			}
	}

	function scan_geniprange($startip,$endip) {
		return array_map("long2ip",range(ip2long($startip),ip2long($endip)));
	}

	function scan_conntest($ip,$port) {
		$fp=@fsockopen($ip,$port,$errno,$errstr,0.1);
		if(!$fp) {
			return false;
		} else {
			fclose($fp);
			return true;
		}
	}

	function scan_exploitable($ip,$proto) {
		$data=@file_get_contents($proto."://".$ip."/web/mediaplayerlist?types=any&path=/tmp/");
			if(!$data) {
				return(false);
			} else {
				return(true);
			}
	}

	function scan_checkheader($ip,$match) {
		$curl=curl_init();
		curl_setopt($curl,CURLOPT_URL,$ip);
		curl_setopt($curl,CURLOPT_HEADER,true);
		curl_setopt($curl,CURLOPT_RETURNTRANSFER,true);
		curl_setopt($curl,CURLOPT_TIMEOUT,5);
		$header=curl_exec($curl);
		curl_close($curl);
		if(preg_match("/".$match."/",$header)) {
			return(true);
		} else {
			return(false);
		}
	}

	// put it all together
	app_checkcli();
	app_checkdep();
	app_header();
	app_run();