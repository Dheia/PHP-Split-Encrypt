# PHP-Split&Encrypt
Packs PHP code to avoid "falsely" detecting it as a malware.
Like for example a nice [reverse shell code](https://github.com/GramThanos/php-smart-reverse-shell).

## About
This code splits the given PHP code on the SPLIT&ENCRYPTme flag and 
packs the rest of the file into an self decrypted AES encryption using
openssl_encrypt. The aim of the code is to hide a malicious code from
anti-virus softwares.

This tool may be used for legal purposes only.  Users take full responsibility
for any actions performed using this tool.  The author accepts no liability
for damage caused by this tool.  If these terms are not acceptable to you, then
do not use this tool.

## Excecution
Get the tool:
```shell
wget -O split-encrypt.php https://github.com/GramThanos/PHP-Split-Encrypt/releases/download/v0.1/split-encrypt.php
```
Then pack the code in `input.php` and export it to `output.php`:
```shell
php split-encrypt.php input.php output.php
```

## Example usage
Pack the whole code:
```shell
gramthanos:~$ echo '<?php echo("Hello world!\n");' > input.php
gramthanos:~$ php split-encrypt.php input.php output.php
Insert password [banana]:
No SPLIT&ENCRYPTme flag found. Packing the whole code...
Saved as output.php
gramthanos:~$ cat output.php
<?php
// SPLIT&ENCRYPTed
eval(openssl_decrypt(
    base64_decode('+jl76F7KLZNowsnWCubzjeQcatkR8EVAOwaZ2K7pc7c5y4rVZeX3SpJt4mqJdKJv'),
    'AES-256-CBC',
    base64_decode('tJPUg2Sv5E0RwBZc9HCkFk0eJgmRHvmYvoaNRq3j3k4='),
    OPENSSL_RAW_DATA,
    base64_decode('2plZelDpjPI6ZuNlqUdlTg==')
));
gramthanos:~$ php output.php
Hello world!
```

Pack second half of a code:

```shell
gramthanos:~$ echo '<?php echo("Hello ");
> // SPLIT&ENCRYPTme
> echo("world!\n");' > input.php
gramthanos:~$ php split-encrypt.php input.php output.php
Insert password [banana]:
Saved as output.php
gramthanos:~$ cat output.php
<?php echo("Hello ");
// SPLIT&ENCRYPTed
eval(openssl_decrypt(
    base64_decode('25yVIdJRfs4wz2cEEVAWpEAfB8onqDE6ofp2D5d1Gbc='),
    'AES-256-CBC',
    base64_decode('tJPUg2Sv5E0RwBZc9HCkFk0eJgmRHvmYvoaNRq3j3k4='),
    OPENSSL_RAW_DATA,
    base64_decode('19upBbxqpyFzTgMUfOmgMg==')
));
gramthanos:~$ php output.php
Hello world!
```

## Copyright & Licence

Copyright (C) 2020 GramThanos
GNU GENERAL PUBLIC LICENSE Version 3
