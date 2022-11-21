# Secure-Communication-System
Allows users to communicate with each other with public and private keys through the local file system

## Report
For my system, it uses 128 bit AES keys for encrypting and decrypting the messages. The AES
mode uses Galois/Counter Mode. The AES key is also used for the MAC. The MAC uses the
"HmacSHA1" algorithm. When generating a  key pair for RSA, it creates a 1024 bit key with a
secureRandom included in the generation. The program is workable on the Windows file
structure. <br><br>
When first running the program, it will create a master folder called "Secure Communication
System" in Documents which houses 3 other folders, namely, "Public Keys", "Private Keys", and
"Transmitted Data". Note that the "Private Keys" folder is only for testing convenience and an
actual user of the system would not have access to that folder. Next, you'll be shown a menu
with 6 options: (1) Generate a key pair, (2) Show public keys, (3) Show transmitted data, (4)
Send a message, (5) Read a message, and 6) Exit. Choosing (1) generates an RSA key pair
which is shown to the user and subsequently stored in the appropriate folders. Choosing (2) lists
all the public key files in the "Public Keys" folder if any exist. And to see the specific contents of
a singular file either type the name of the file or type the path to a public key file in quotes. I
made it this way because in Windows when copying a path you have to Shift + Right Click and
then Copy as Path and that copies the full path to the file in quotes so it was easier to test with.
Choosing (3) shows all the transmitted data that have been sent over the channel. The contents
of a singular transmitted data file include the encrypted message, the encrypted AES key, and
the MAC. Choosing (4) allows the user to send a message to a receiver by providing the
message file path and the intended recipient's public key file or public key file name. An AES
key is generated and encrypts the message contents. The AES key is then encrypted with the
receiver's public key. And the MAC is generated with the encrypted message and the AES key.
And all of this is saved in a transmitted data file which is stored in the "Transmitted Data" folder.
Choosing (5) allows the user to read a message from a sender by providing the message file
path and the user's own private key file (or private key file name for convenience and testing
purposes). The AES key is decrypted using the private key and used with the encrypted
message in the MAC algorithm to authenticate the message. Once authenticated, the AES key
is then used to decrypt the encrypted message which is then displayed to the user. And finally,
choosing any other key allows the user to exit the program. <br><br>
This system is definitely vulnerable to attack. Firstly, there is no way to tell where a message
came from. This can be solved by mandating a user to provide their private key when sending a
message to create a digital signature. It's vulnerable to a replay attack. And this can be solved
by adding a nonce to ensure originality. It's vulnerable to a delayed attack where a malicious
entity receives the file and holds onto it and sends it at a later date. This can be solved by
attaching a timestamp to the files to ensure that the files were sent in a timely manner. And of
course the system like all other systems is vulnerable to a brute force attack. Otherwise, the
system is generally secure, other than having the Private Keys folder which is purely for testing.
