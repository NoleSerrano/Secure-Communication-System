import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
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
import java.security.spec.PKCS8EncodedKeySpec;
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
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

// Resources
// https://gustavopeiretti.com/rsa-encrypt-decrypt-java/
// https://www.tutorialspoint.com/java_cryptography/java_cryptography_creating_mac.htm

// Shift + Right Click file > Copy as path > "C:\Users\%USERNAME%\Documents\Secure Communication System\Private Keys\%FILENAME%.txt"
public class SecureCommunicationSystem {

	private static Base64.Encoder encoder = Base64.getEncoder(); // used for encoding the RSA key into text
	private static Cipher encryptionCipher;

	public static void main(String[] args) throws Exception {
		Scanner sc = new Scanner(System.in);
		String home = System.getProperty("user.home");

		File channel = new File(home + "\\Documents\\Secure Communication System"); // Windows file
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

		print("Secure Communication System\n");
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
				readMessage(sc, publicKeysFolder, privateKeysFolder, transmittedDataFolder);
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
			String fileName = sc.nextLine();
			if (fileName.length() != 0) { // user didn't press enter
				fileName += ".txt";
				String publicKeyString = new String(
						Files.readAllBytes(Paths.get(publicKeysFolder.getAbsoluteFile() + "\\" + fileName)),
						StandardCharsets.UTF_8);
				print(formatPublicKey(publicKeyString) + "\n");
			}
		}

	}

	private static void showTransmittedData(Scanner sc, File transmittedDataFolder) throws IOException {
		File[] transmittedDataFiles = transmittedDataFolder.listFiles();

		if (transmittedDataFiles.length != 0) {
			print("-----BEGIN TRANSMITTED DATA-----\n");
			for (File transmittedDataFile : transmittedDataFiles) {
				print(transmittedDataFile.getName().substring(0, transmittedDataFile.getName().length() - 4) + "\n");
			}
			print("-----END TRANSMITTED DATA-----\n");
			print("File name: "); // file name of specific transmitted data
			String fileName = sc.nextLine();
			if (fileName.length() != 0) { // user didn't press enter
				fileName += ".txt";
				String transmittedDataString = new String(
						Files.readAllBytes(Paths.get(transmittedDataFolder.getAbsoluteFile() + "\\" + fileName)),
						StandardCharsets.UTF_8);
				print(formatTransmittedData(transmittedDataString) + "\n");
			}
		}
	}

	private static String formatTransmittedData(String s) {
		String[] data = s.split("\n");
		String formatted = "";
		// encrypted message
		formatted += ("-----BEGIN ENCRYPTED MESSAGE-----\n");
		formatted += (formatLongString(data[0]) + "\n");
		formatted += ("-----END ENCRYPTED MESSAGE-----\n");

		// encrypted AES key
		formatted += ("-----BEGIN ENCRYPTED AES KEY-----\n");
		formatted += (formatLongString(data[1]) + "\n");
		formatted += ("-----END ENCRYPTED AES KEY-----\n");

		// MAC
		formatted += ("-----BEGIN MAC RESULT-----\n");
		formatted += (formatLongString(data[2]) + "\n");
		formatted += ("-----END MAC RESULT-----");

		return formatted;
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
		print("Message file: "); // sender's message (full path to file)
		String messageFileName = sc.nextLine();
		if (messageFileName.contains("\"")) { // copy as path
			messageFileName = messageFileName.substring(1, messageFileName.length() - 1);
		}
		File messageFile = new File(messageFileName);
		String messageString = Files.readString(Paths.get(messageFile.getAbsolutePath()));

		print("Their public key file: "); // intended recipient's public key
		String receiversPublicKeyFileName = sc.nextLine();
		File receiversPublicKeyFile;
		if (receiversPublicKeyFileName.contains("\"")) { // copy as path --> surrounds full path with quotes and quotes
															// are disallowed in file names
			receiversPublicKeyFile = new File(
					receiversPublicKeyFileName.substring(1, receiversPublicKeyFileName.length() - 1));
		} else {
			receiversPublicKeyFile = new File(
					publicKeysFolder.getAbsolutePath() + "\\" + receiversPublicKeyFileName + ".txt");
		}

		SecretKey aesKey = generateAESKey(); // generate AES key for message

		String encryptedMessage = encryptAES(messageString, aesKey); // encrypted message using AES key

		// encrypted AES key
		String encryptedAesKey = encryptRSA(secretKeyToString(aesKey), receiversPublicKeyFile, true);

		String macResult = generateMAC(encryptedMessage, aesKey); // mac of encrypted message with AES key

		// display info to user
		print("-----BEGIN ENCRYPTED MESSAGE-----\n");
		print(formatLongString(encryptedMessage) + "\n");
		print("-----END ENCRYPTED MESSAGE-----\n");

		print("-----BEGIN ENCRYPTED AES KEY-----\n");
		print(formatLongString(encryptedAesKey) + "\n");
		print("-----END ENCRYPTED AES KEY-----\n");

		print("-----BEGIN MAC RESULT-----\n");
		print(formatLongString(macResult) + "\n");
		print("-----END MAC RESULT-----\n");

		FileWriter fileWriter = new FileWriter(transmittedData);
		// encrypted message, encrypted AES key, and mac result stored in file (and also
		// IV because that's needed in AES decryption)
		fileWriter.write(
				encryptedMessage + "\n" + encryptedAesKey + "\n" + macResult + "\n" + encode(encryptionCipher.getIV()));
		fileWriter.close();
	}

	private static void readMessage(Scanner sc, File publicKeysFolder, File privateKeysFolder,
			File transmittedDataFolder) throws Exception {
		print("File name: "); // message receiver wants to read
		String fileName = sc.nextLine();
		// gets the transmitted data content
		String[] data;
		if (fileName.contains("\"")) {
			String transmittedDataString = new String(
					Files.readAllBytes(Paths.get(fileName.substring(1, fileName.length() - 1))));
			data = transmittedDataString.split("\n");
		} else {
			String transmittedDataString = new String(
					Files.readAllBytes(Paths.get(transmittedDataFolder.getAbsolutePath() + "\\" + fileName + ".txt")));
			data = transmittedDataString.split("\n");
		}

		print("Your private key file: "); // private key of receiver
		String privateKeyFileName = sc.nextLine();
		File privateKeyFile;
		if (privateKeyFileName.contains("\"")) { // copy as path --> surrounds full path with quotes and quotes are
													// disallowed in file names
			privateKeyFile = new File(privateKeyFileName.substring(1, privateKeyFileName.length() - 1));
		} else {
			privateKeyFile = new File(privateKeysFolder.getAbsoluteFile() + "\\" + privateKeyFileName + ".txt");
		}

		String encryptedMessage = data[0];
		String encryptedAesKey = data[1];
		String macResult = data[2];
		byte[] iv = decode(data[3]);

		// decrypt AES key with RSA private key
		String aesKeyString = decodeBase64String(decryptRSA(encryptedAesKey, privateKeyFile, false));
		SecretKey aesKey = stringToSecretKey(aesKeyString);

		String receiversMacResult = generateMAC(encryptedMessage, aesKey);
		if (receiversMacResult.equals(macResult)) { // hash is same
			print("Message authenticated\n");
		} else {
			print("Error: Message cannot be authenticated\n");
			return;
		}

		encryptionCipher = Cipher.getInstance("AES/GCM/NoPadding");
		encryptionCipher.init(Cipher.ENCRYPT_MODE, aesKey);
		String message = decodeBase64String(decryptAES(encryptedMessage, aesKey, iv));
		print("-----BEGIN MESSAGE-----\n");
		print(message + "\n");
		print("-----END MESSAGE-----\n");
	}

	public static String secretKeyToString(SecretKey secretKey) throws NoSuchAlgorithmException {
		byte[] rawData = secretKey.getEncoded();
		String encodedKey = Base64.getEncoder().encodeToString(rawData);
		return encodedKey;
	}

	public static SecretKey stringToSecretKey(String encodedKey) {
		byte[] decodedKey = Base64.getDecoder().decode(encodedKey);
		SecretKey originalKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
		return originalKey;
	}

	private static void print(Object o) {
		System.out.print(o.toString());
	}

	private static SecretKey generateAESKey() throws NoSuchAlgorithmException {
		KeyGenerator keyGen = KeyGenerator.getInstance("AES");
		keyGen.init(128); // # of bits
		SecretKey aesKey = keyGen.generateKey();
		return aesKey;
	}

	private static String generateMAC(String messageString, SecretKey aesKey)
			throws NoSuchAlgorithmException, InvalidKeyException, InvalidKeySpecException, IOException {
		Mac mac = Mac.getInstance("HmacSHA1"); // algorithm
		SecretKeySpec signingKey = new SecretKeySpec(aesKey.getEncoded(), "HmacSHA1");
		mac.init(signingKey); // init mac with key
		byte[] macResult = mac.doFinal(decode(messageString)); // result of mac
		return encode(macResult);
	}

	public static String encryptAES(String messageToEncrypt, SecretKey aesKey) throws Exception {
		byte[] messageBytes = messageToEncrypt.getBytes(); // bytes of message
		encryptionCipher = Cipher.getInstance("AES/GCM/NoPadding");
		encryptionCipher.init(Cipher.ENCRYPT_MODE, aesKey);
		byte[] encryptedBytes = encryptionCipher.doFinal(messageBytes); // encrypts with AES
		return encode(encryptedBytes);
	}

	public static String decryptAES(String cipherToDecrypt, SecretKey aesKey, byte[] iv) throws Exception {
		byte[] dataInBytes = decode(cipherToDecrypt); // bytes of message
		Cipher decryptionCipher = Cipher.getInstance("AES/GCM/NoPadding");
		GCMParameterSpec spec = new GCMParameterSpec(128, iv); // first param is data length and
																// is 128 bits
		decryptionCipher.init(Cipher.DECRYPT_MODE, aesKey, spec);
		byte[] decryptedBytes = decryptionCipher.doFinal(dataInBytes); // decrypts with AES
		return encode(decryptedBytes);
	}

	private static String encryptRSA(String messageToEncrypt, File keyFile, boolean isPublicKey)
			throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException,
			NoSuchPaddingException, InvalidKeySpecException, IOException {
		Key key = loadKey(keyFile, isPublicKey, "RSA"); // load the key
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.ENCRYPT_MODE, key);
		byte[] bytes = cipher.doFinal(messageToEncrypt.getBytes(StandardCharsets.UTF_8)); // encrypts the message
		return encode(bytes);
	}

	private static String decryptRSA(String cipherToDecrypt, File keyFile, boolean isPublicKey)
			throws NoSuchAlgorithmException, InvalidKeySpecException, IOException, NoSuchPaddingException,
			InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		Key key = loadKey(keyFile, isPublicKey, "RSA"); // load the key
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.DECRYPT_MODE, key);
		byte[] bytes = cipher.doFinal(Base64.getDecoder().decode(cipherToDecrypt)); // decrypts the cipher
		return encode(bytes);
	}

	private static Key loadKey(File keyFile, boolean isPublicKey, String algorithm)
			throws IOException, NoSuchAlgorithmException, InvalidKeySpecException { // loads public or private key
		byte[] keyBytes = decode(Files.readString(Paths.get(keyFile.getAbsolutePath()))); // bytes of key
		KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
		if (isPublicKey) {
			EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
			PublicKey publicKey = keyFactory.generatePublic(keySpec);
			return publicKey;
		} else {
			EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
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

	private static String decodeBase64String(String s) throws UnsupportedEncodingException {
		byte[] decoded = Base64.getDecoder().decode(s);
		return new String(decoded, "UTF-8");
	}

}
