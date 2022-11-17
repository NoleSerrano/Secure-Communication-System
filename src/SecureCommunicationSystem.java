import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Date;
import java.util.Scanner;

public class SecureCommunicationSystem {

	public static void main(String[] args) throws IOException, NoSuchAlgorithmException, NoSuchProviderException {
		Scanner sc = new Scanner(System.in);
//		System.out.println(new Date().getTime());
		String username = System.getProperty("user.name");
		File channel = new File("C:\\Users\\" + username + "\\Documents\\Secure Communication System"); // Windows file
																										// structure
		try {
			channel.mkdir(); // creates Secure Communication Channel folder if doesn't exist
		} catch (Exception e) {
			print(e);
		}

		// creates appropriate folders if they do not exist
		File transmittedDataFolder = new File(channel.getAbsolutePath() + "\\Transmitted Data");
		try {
			transmittedDataFolder.mkdir(); // creates Transmitted Data folder if doesn't exist
		} catch (Exception e) {
			print(e);
		}
		File publicKeysFolder = new File(channel.getAbsolutePath() + "\\Public Keys");
		try {
			publicKeysFolder.mkdir(); // creates Public Keys folder if doesn't exist
		} catch (Exception e) {
			print(e);
		}
		File privateKeysFolder = new File(channel.getAbsolutePath() + "\\Private Keys");
		try {
			privateKeysFolder.mkdir(); // creates Private Keys folder if doesn't exist
		} catch (Exception e) {
			print(e);
		}
		while (true) {
			print("\n1) Generate a key pair\n2) Show public keys\n3) Show transmitted data\n4) Send a message\n5) Read a message\n6) Exit\nChoice: ");
			int choice = sc.nextInt();
			sc.nextLine();
			switch (choice) {
			case 1: // generate key pair

				generateKeyPair(sc, channel);

				break;
			case 2: // show public keys
				showPublicKeys(sc, publicKeysFolder);
				break;
			case 3: // show transmitted data
				showTransmittedData(sc, transmittedDataFolder);
				break;
			case 4: // send a message
				sendMessage(sc);
				break;
			case 5: // read a message
				readMessage(sc);
				break;
			default:
				return;
			}
		}

	}

	private static String formatLongString(String s) {
		String formatted = "";
		int lineLength = 128;
		for (int i = 0; i <= s.length() / lineLength; i++) {
			try {
				formatted += s.substring(i * lineLength, i * lineLength + lineLength) + "\n";
			} catch (Exception e) {
				formatted += s.substring(i * lineLength, s.length());
			}
		}
		return formatted;
	}

	private static String formatPublicKey(String publicKeyString) {
		return "-----BEGIN RSA PUBLIC KEY-----\n" + formatLongString(publicKeyString)
				+ "\n-----END RSA PUBLIC KEY-----";
	}

	private static String formatPrivateKey(String privateKeyString) {
		return "-----BEGIN RSA PRIVATE KEY-----\n" + formatLongString(privateKeyString)
				+ "\n-----END RSA PRIVATE KEY-----";
	}

	private static void generateKeyPair(Scanner sc, File channel)
			throws NoSuchAlgorithmException, IOException, NoSuchProviderException {
		// generates RSA public and private key
		// public and private key are shown to user and stored in appropriate folders

		print("\nOptional file name: "); // optional file name otherwise will just use date as file name
		String optionalFileName = sc.nextLine();
		if (optionalFileName.length() == 0) { // default ENTER, get time for file name
			optionalFileName = new Date().getTime() + "";
		}
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA"); // class to generate keys
		SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG"); // for randomness
		byte[] bytes = new byte[20];
		secureRandom.nextBytes(bytes);
		keyPairGenerator.initialize(1024, secureRandom); // RSA key pair generator will now generate 1024 bit key size
		KeyPair keyPair = keyPairGenerator.generateKeyPair(); // generates the public and private RSA keys
		Key publicKey = keyPair.getPublic(); // public RSA key
		Key privateKey = keyPair.getPrivate(); // private RSA key
		Base64.Encoder encoder = Base64.getEncoder(); // used for encoding the RSA key into text

		String publicKeyString = encoder.encodeToString(publicKey.getEncoded());
		String privateKeyString = encoder.encodeToString(privateKey.getEncoded());
		String publicKeyFormatted = formatPublicKey(publicKeyString);
		String privateKeyFormatted = formatPrivateKey(privateKeyString);

		FileWriter fileWriter = null;

		if (optionalFileName.length() > 0) {
			File publicKeyFile = new File(channel.getAbsoluteFile() + "\\Public Keys\\" + optionalFileName + ".txt");
			int i = 0;
			if (!publicKeyFile.createNewFile()) {
				i = 1;
				while (true) { // looks for a file name until one doesn't exist
					publicKeyFile = new File(
							channel.getAbsoluteFile() + "\\Public Keys\\" + optionalFileName + " (" + i + ").txt");
					if (publicKeyFile.createNewFile()) {
						break;
					} else {
						i++;
					}
				}
			}
			fileWriter = new FileWriter(publicKeyFile);
			fileWriter.write(publicKeyString); // writes the public key into the file
			fileWriter.close();
			print("\n" + publicKeyFile.getAbsolutePath());
			print("\n" + publicKeyFormatted + "\n");

			File privateKeyFile;
			if (i == 0) {
				privateKeyFile = new File(channel.getAbsoluteFile() + "\\Private Keys\\" + optionalFileName + ".txt");
			} else {
				privateKeyFile = new File(
						channel.getAbsoluteFile() + "\\Private Keys\\" + optionalFileName + " (" + i + ").txt");
			}
			fileWriter = new FileWriter(privateKeyFile);
			fileWriter.write(privateKeyString); // writes the private key into the file (note that no user should be
												// able
												// to read the private keys, this is just for testing sake)
			fileWriter.close();
			print("\n" + privateKeyFile.getAbsolutePath());
			print("\n" + privateKeyFormatted + "\n");
		}
	}

	private static void showPublicKeys(Scanner sc, File publicKeysFolder) throws IOException {
		// displays all public key files
		File[] publicKeyFiles = publicKeysFolder.listFiles();

		if (publicKeyFiles.length != 0) {
			print("\n");
			for (File publicKeyFile : publicKeyFiles) {
				print(publicKeyFile.getName().substring(0, publicKeyFile.getName().length() - 4) + "\n");
			}
			print("\n");
			print("File name: "); // file name of specific public key
			String fileName = sc.nextLine() + ".txt";
			if (fileName.length() != 0) { // user didn't press enter
				String publicKeyString = new String(
						Files.readAllBytes(Paths.get(publicKeysFolder.getAbsoluteFile() + "\\" + fileName)),
						StandardCharsets.UTF_8);
				print("\n" + formatPublicKey(publicKeyString) + "\n");

			}
		}

	}

	private static void showTransmittedData(Scanner sc, File transmittedDataFolder) {
		print("File keyword: "); // shows all messages that have the keyword
	}

	private static void sendMessage(Scanner sc) {
		print("Optional file name: "); // optional file name otherwise will just use the date as file name
		String optionalFileName = sc.nextLine();
		if (optionalFileName.length() == 0) { // default ENTER, get time for file name
			optionalFileName = new Date().getTime() + "";
		}

		print("Message: "); // sender's message
		String message = sc.nextLine(); // send empty messages?

		print("Receiver's public key file: "); // intended recipient's public key
		String receiversPublicKeyFile = sc.nextLine();

		print("Your private key file: "); // private key of sender
		String sendersPrivateKeyFile = sc.nextLine();

	}

	private static void readMessage(Scanner sc) {
		print("File name: "); // message receiver wants to read
		print("Your private key file"); // private key of receiver
		print("Sender's public key file"); // public key of sender for verification
	}

	private static void print(Object o) {
		System.out.print(o.toString());
	}

}
