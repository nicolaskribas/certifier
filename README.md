# certifier

## Compiling 

This project uses rust language and cargo package manager. You can run it using `cargo run` command.

## Usage

### Generate a certificate

```sh
certifier generate --credentials "Bob bob@example.com" --pubkey bob_key.pub --privkey bob_key --output certificates/bob
```
This command will create a certificate named `bob.certificate` on `certificates/` folder.

`bob_key.pub` and `bob_key` are public and private key in OpenSSH format. They can be generated using ssh-keygen like this: `ssh-keygen -f bob_key -N ""`.

### Sign a document

```sh
certifier sign --document bob_document.txt --certificate certificates/bob.certficicate --privkey bob_key
```
This command will create a detatched signature named `bob_document.signature` for the content of file `bob_document.txt`.

### Checking document signature

```sh
certifier check --document bob_document.txt --trust certificates/
```
This commmand will look for the right certificate into `certificates/` folder and will check the integrity of `bob_document.txt` using the public key present
in the certificate printing a message with the result.

## Help

To get help with all the options and commands run this program using the `-h` flag: `certifier <SUBCOMMAND> -h`

The subcommands are `generate`, `sign` and `check`.
