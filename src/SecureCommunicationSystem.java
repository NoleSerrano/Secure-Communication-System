import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.security.*;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.Random;
import java.util.Scanner;

public class SecureCommunicationSystem {

	public static void main(String[] args) throws IOException, NoSuchAlgorithmException, NoSuchProviderException {
		Scanner sc = new Scanner(System.in);
//		System.out.println(new Date().getTime());
		File channel;
		do {
			print("Secure Communication Channel: "); // file path to Public Keys and Transmitted Data
			String channelFilePath = sc.nextLine();
			channel = new File(channelFilePath);
			if (!channel.exists()) {
				print("Invalid file path\n\n");
			}
		} while (!channel.exists());

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
				showTransmittedData(sc);
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

	private static void generateKeyPair(Scanner sc, File channel)
			throws NoSuchAlgorithmException, IOException, NoSuchProviderException {
		// generates RSA public and private key
		// public and private key are shown to user and stored in appropriate folders
		// file name of both public and private key are the same and use Date.now()

		print("Optional file name: "); // optional file name which will be appended with Date.now()
		String optionalFileName = sc.nextLine();
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA"); // class to generate keys
		SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG"); // for randomness
		byte[] bytes = new byte[20];
		secureRandom.nextBytes(bytes);
		print("\n" + secureRandom + "\n");
		keyPairGenerator.initialize(1024, secureRandom); // RSA key pair generator will now generate 1024 bit key size
		KeyPair keyPair = keyPairGenerator.generateKeyPair(); // generates the public and private RSA keys
		Key publicKey = keyPair.getPublic(); // public RSA key
		Key privateKey = keyPair.getPrivate(); // private RSA key
		Base64.Encoder encoder = Base64.getEncoder(); // used for encoding the RSA key into text

		String publicKeyText = "-----BEGIN RSA PUBLIC KEY-----\n"
				+ formatLongString(encoder.encodeToString(publicKey.getEncoded())) + "\n-----END RSA PUBLIC KEY-----";
		String privateKeyText = "-----BEGIN RSA PRIVATE KEY-----\n"
				+ formatLongString(encoder.encodeToString(privateKey.getEncoded())) + "\n-----END RSA PRIVATE KEY-----";

		if (optionalFileName.length() == 0) { // default ENTER, get time for file name
			optionalFileName = new Date().getTime() + "";
		}
		FileWriter fileWriter = null;

		if (optionalFileName.length() > 0) {
			File publicKeyFile = new File(channel.getAbsoluteFile() + "\\Public Keys\\" + optionalFileName + ".txt");
			fileWriter = new FileWriter(publicKeyFile);
			fileWriter.write(publicKeyText); // writes the public key into the file
			fileWriter.close();
			print("\n" + publicKeyFile.getAbsolutePath());
			print("\n" + publicKeyText + "\n");

			File privateKeyFile = new File(channel.getAbsoluteFile() + "\\Private Keys\\" + optionalFileName + ".txt");
			fileWriter = new FileWriter(privateKeyFile);
			fileWriter.write(privateKeyText); // writes the private key into the file (note that no user should be able
												// to read the private keys, this is just for testing sake)
			fileWriter.close();
			print("\n" + privateKeyFile.getAbsolutePath());
			print("\n" + privateKeyText + "\n");
		}
	}

	private static void showPublicKeys(Scanner sc, File publicKeysFolder) {
		// displays all public key files

		print("File name: "); // file name of specific public key
		// shows the actual public key in the terminal
	}

	private static void showTransmittedData(Scanner sc) {
		print("File keyword: "); // shows all messages that have the keyword
	}

	private static void sendMessage(Scanner sc) {
		print("Optional file name: "); // optional file name which will be appended with Date.now()
		print("Message: "); // sender's message
		print("Receiver's public key: "); // intended recipient's public key
		print("Sender's private key: "); // private key of sender

	}

	private static void readMessage(Scanner sc) {
		print("File name: "); // message receiver wants to read
		print("Receiver's private key"); // private key of receiver
		print("Sender's public key"); // public key of sender for verification
	}

	private static void print(Object o) {
		System.out.print(o.toString());
	}

}
