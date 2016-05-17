<?php

/*
#
# [ nScan ]
# Version: 0.1beta
#	
#
*/

class scanning {

	private $protection_array = array('mysql_real_escape_string', 'escape_string', 'escape', 'htmlspecialchars', 'htmlentities', '(int)', 'escapeString');
	private $input_array = array('\$_SERVER','\$_GET','\$_POST','\$_COOKIE','\$_REQUEST','\$_FILES','\$_ENV','\$_HTTP_COOKIE_VARS','\$_HTTP_ENV_VARS','\$_HTTP_POST_FILES','\$_HTTP_GET_VARS','\$_HTTP_POST_VARS','\$_HTTP_SERVER_VARS','\$_FILES');
	public $search;

	public function help($error) {
		$banner = "
      ____                               
     /\  _`\                             
  ___\ \,\L\_\    ___     __      ___    
/' _ `\/_\__ \   /'___\ /'__`\  /' _ `\  
/\ \/\ \/\ \L\ \/\ \__//\ \L\.\_/\ \/\ \ 
\ \_\ \_\ `\____\ \____\ \__/.\_\ \_\ \_\
 \/_/\/_/\/_____/\/____/\/__/\/_/\/_/\/_/                       
Options:
	-a -- Attack Type;
		scan - Scans directory for potential bugs.
		show - Shows sourcecode of file (needs -f).
		search - Search's for specified query
	-d
		directory - directory to scan.
	-f
		file - Shows file sourcecode.
	-q
		query - Query to search.";

		if(!empty($error)) {
			if($error == "attack") {
				$banner .= "\n ERROR: Missing option -a \n";
			} elseif($error == "file") {
				$banner .= "\n ERROR: Missing option -f \n";
			} elseif($error == "directory") {
				$banner .= "\n ERROR: Missing option -d \n";
			} elseif($error == "search") {
				$banner .= "\n ERROR: Missing option -q \n";
			}
		}
		echo $banner;
	}

	public function find_files($directory, $type) {
		$path = new RecursiveDirectoryIterator($directory);
		foreach(new RecursiveIteratorIterator($path) as $filename=>$cur) {
			if(strpos($filename, ".php")) {
				if($type == 1) {
					$this->search_file($filename);
				} elseif($type == 2) {
					$this->search_query($filename);
				}
			}
		}
	}

	private function check_secure($line) {
		$error = 0;
		foreach($this->protection_array as $test_cause) {
			if(preg_match("/$test_cause/i", $line)) {
				$error = 1;
			}
		}
		if($error == 1) {
			return false;
		} elseif($error == 0) {
			return true;
		}
	}

	private function search_file($file) {
		$fh = new SplFileObject($file);
		while(!$fh->eof()) {
			$line = $fh->fgets();
			$line_number = $fh->key();
			foreach($this->input_array as $test_cause) {
				if(preg_match("/$test_cause/i", $line)) {
					if(preg_match("/=.*$test_cause/i", $line)) {
						if($this->check_secure($line) != false) {
							echo "File: ".$file."\nLine Number: ".$line_number."\nLine: ".ltrim($line).PHP_EOL;
						}
					}
				}
			}
		}
	}

	private function search_query($file) {
		$fh = new SplFileObject($file);
		while(!$fh->eof()) {
			$line = $fh->fgets();
			$line_number = $fh->key();
			if(preg_match("/$this->query/i", $line)) {
				echo "File: ".$file."\nLine Number: ".$line_number."\nLine: ".ltrim($line).PHP_EOL;
			}
		}
	}

	private function get_variable($line, $test_cause) {
		preg_match("/^\$(.*)=.*$test_cause/", $line, $output);
		if(!empty($output)) {
			if(!empty($output[1])) {

			}
		}
	}
}


$a = new scanning;

if(empty($argv[1])) {
	die($a->help(''));
} else {
	if($key = array_search('-h', $argv)) {
		die($a->help(''));
	}
	if($key = array_search('-a', $argv)) {
		$type = $argv[$key+1];
	} else {
		die($a->help('attack'));
	}
	if($key = array_search('-d', $argv)) {
		$directory = $argv[$key+1];
	} else {
		if($type == "scan") {
			die($a->help('directory'));
		} elseif($type == "search") {
			die($a->help('directory'));
		}
	}
	if($key = array_search('-f', $argv)) {
		$file = $argv[$key+1];
	} else {
		if($type == "show") {
			die($a->help('file'));
		}
	}
	if($key = array_search('-q', $argv)) {
		$search = $argv[$key+1];
	} else {
		if($type == "search") {
			die($a->help('search'));
		}
	}
}

if($type == "scan") {
	$a->find_files($directory, 1);
} elseif($type == "show") {
	show_source($file);
} elseif($type == "search") {
	$a->query = $search;
	$a->find_files($directory, 2);
}


?>
