import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Date;
import java.util.Scanner;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.util.Base64;

public class SecureCommunicationSystem {

	private static Base64.Encoder encoder = Base64.getEncoder(); // used for encoding the RSA key into text
	private static Cipher encryptionCipher;

	public static void main(String[] args) throws Exception {
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
				sendMessage(sc, publicKeysFolder, privateKeysFolder, transmittedDataFolder);
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

	public static void generateKeyPair(Scanner sc, File channel)
			throws NoSuchAlgorithmException, IOException, NoSuchProviderException {
		// generates RSA public and private key
		// public and private key are shown to user and stored in appropriate folders

		print("Optional file name: "); // optional file name otherwise will just use date as file name
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
			print(publicKeyFile.getAbsolutePath());
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
			print(privateKeyFile.getAbsolutePath());
			print("\n" + privateKeyFormatted + "\n");
		}
	}

	private static void showPublicKeys(Scanner sc, File publicKeysFolder) throws IOException {
		// displays all public key files
		File[] publicKeyFiles = publicKeysFolder.listFiles();

		if (publicKeyFiles.length != 0) {
			print("-----BEGIN PUBLIC KEYS-----\n");
			for (File publicKeyFile : publicKeyFiles) {
				print(publicKeyFile.getName().substring(0, publicKeyFile.getName().length() - 4) + "\n");
			}
			print("-----END PUBLIC KEYS-----\n");
			print("File name: "); // file name of specific public key
			String fileName = sc.nextLine() + ".txt";
			if (fileName.length() != 0) { // user didn't press enter
				String publicKeyString = new String(
						Files.readAllBytes(Paths.get(publicKeysFolder.getAbsoluteFile() + "\\" + fileName)),
						StandardCharsets.UTF_8);
				print(formatPublicKey(publicKeyString) + "\n");

			}
		}

	}

	private static void showTransmittedData(Scanner sc, File transmittedDataFolder) {
		print("File keyword: "); // shows all messages that have the keyword
	}

	private static void sendMessage(Scanner sc, File publicKeysFolder, File privateKeysFolder,
			File transmittedDataFolder) throws Exception {
//		AES key to encrypt file message and then RSA to encrypt AES key and they are wrapped together
//		store it in text file – new line to separate encrypted AES key, encrypted message, and MAC

		print("Optional file name: "); // optional file name otherwise will just use the date as file name
		String optionalFileName = sc.nextLine();
		if (optionalFileName.length() == 0) { // default ENTER, get time for file name
			optionalFileName = new Date().getTime() + "";
		}

		File transmittedData = new File(transmittedDataFolder.getAbsolutePath() + "\\" + optionalFileName + ".txt");
		if (!transmittedData.createNewFile()) {
			int i = 1;
			while (true) {
				transmittedData = new File(
						transmittedDataFolder.getAbsolutePath() + "\\" + optionalFileName + " (" + i + ").txt");
				if (transmittedData.createNewFile()) {
					break;
				} else {
					i++;
				}
			}
		}
		print("Message file: "); // sender's message
		File messageFile = new File(sc.nextLine());
		byte[] messageBytes = Files.readAllBytes(Paths.get(messageFile.getAbsolutePath()));
		String messageString = messageBytes.toString();

		print("Receiver's public key file: "); // intended recipient's public key
		String receiversPublicKeyFileName = sc.nextLine();
		File receiversPublicKeyFile = new File(
				publicKeysFolder.getAbsolutePath() + "\\" + receiversPublicKeyFileName + ".txt");

		print("Your private key file: "); // private key of sender
		String sendersPrivateKeyFileName = sc.nextLine();
		File sendersPrivateKeyFile = new File(
				privateKeysFolder.getAbsoluteFile() + "\\" + sendersPrivateKeyFileName + ".txt");

		SecretKey aesKey = generateAESKey(); // generate AES key for message
		String encryptedMessage = encrypt(messageString, aesKey); // encrypted message using AES key
		String encryptedAesKey = encrypt(aesKey.toString(), receiversPublicKeyFile, true, "RSA"); // encrypted AES key

	}

	private static void readMessage(Scanner sc) {
		print("File name: "); // message receiver wants to read
		print("Your private key file"); // private key of receiver
		print("Sender's public key file"); // public key of sender for verification
	}

	private static void print(Object o) {
		System.out.print(o.toString());
	}

	private static SecretKey generateAESKey() throws NoSuchAlgorithmException {
		KeyGenerator keyGen = KeyGenerator.getInstance("AES");
		keyGen.init(256); // 256 bits
		SecretKey aesKey = keyGen.generateKey();
		return aesKey;
	}

	private static byte[] generateMAC(byte[] messageBytes, Key key)
			throws NoSuchAlgorithmException, InvalidKeyException {
		Mac mac = Mac.getInstance("HmacSHA256"); // SHA 256 algorithm
		mac.init(key); // init mac with key
		byte[] macResult = mac.doFinal(messageBytes); // result of mac
		return macResult;
	}

	// encrypt with AES
	public static String encrypt(String messageToEncrypt, SecretKey aesKey) throws Exception {
		byte[] messageBytes = messageToEncrypt.getBytes();
		encryptionCipher = Cipher.getInstance("AES/GCM/NoPadding");
		encryptionCipher.init(Cipher.ENCRYPT_MODE, aesKey);
		byte[] encryptedBytes = encryptionCipher.doFinal(messageBytes);
		return encode(encryptedBytes);
	}

	// decrypt with AES
	public static String decrypt(String cipherToDecrypt, SecretKey aesKey) throws Exception {
		byte[] dataInBytes = decode(cipherToDecrypt);
		Cipher decryptionCipher = Cipher.getInstance("AES/GCM/NoPadding");
		GCMParameterSpec spec = new GCMParameterSpec(128, encryptionCipher.getIV()); // first param is data length and
																						// is 128 bits
		decryptionCipher.init(Cipher.DECRYPT_MODE, aesKey, spec);
		byte[] decryptedBytes = decryptionCipher.doFinal(dataInBytes);
		return new String(decryptedBytes);
	}

	private static String encrypt(String messageToEncrypt, File keyFile, boolean isPublicKey, String algorithm)
			throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException,
			NoSuchPaddingException, InvalidKeySpecException, IOException {
		Key key = loadKey(keyFile, isPublicKey, algorithm);
		Cipher cipher = Cipher.getInstance(algorithm);
		cipher.init(Cipher.ENCRYPT_MODE, key);
		byte[] bytes = cipher.doFinal(messageToEncrypt.getBytes(StandardCharsets.UTF_8));
		return new String(Base64.getEncoder().encode(bytes));
	}

	private static String decrypt(String cipherToDecrypt, File keyFile, boolean isPublicKey, String algorithm)
			throws NoSuchAlgorithmException, InvalidKeySpecException, IOException, NoSuchPaddingException,
			InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		Key key = loadKey(keyFile, isPublicKey, algorithm);
		Cipher cipher = Cipher.getInstance(algorithm);
		cipher.init(Cipher.DECRYPT_MODE, key);
		byte[] bytes = cipher.doFinal(Base64.getDecoder().decode(cipherToDecrypt));
		return new String(bytes);
	}

	private static Key loadKey(File keyFile, boolean isPublicKey, String algorithm)
			throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
		byte[] keyBytes = SecureCommunicationSystem.class.getResourceAsStream(keyFile.getAbsolutePath()).readAllBytes();
		KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
		EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
		if (isPublicKey) {
			PublicKey publicKey = keyFactory.generatePublic(keySpec);
			return publicKey;
		} else {
			PrivateKey privateKey = keyFactory.generatePrivate(keySpec);
			return privateKey;
		}
	}

	private static String encode(byte[] data) {
		return Base64.getEncoder().encodeToString(data);
	}

	private static byte[] decode(String data) {
		return Base64.getDecoder().decode(data);
	}

}
