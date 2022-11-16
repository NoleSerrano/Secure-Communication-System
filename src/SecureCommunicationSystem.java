import java.io.File;
import java.util.Date;
import java.util.Scanner;

public class SecureCommunicationSystem {

	public static void main(String[] args) {
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
		while (true) {
			print("\n1) Generate a key pair\n2) Show public keys\n3) Show transmitted data\n4) Send a message\n5) Read a message\n6) Exit\nChoice: ");
			int choice = sc.nextInt();
			sc.nextLine();
			switch (choice) {
			case 1: // generate key pair
				generateKeyPair(sc);
				break;
			case 2: // show public keys
				showPublicKeys(sc);
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

	private static void generateKeyPair(Scanner sc) {
		// generates RSA public and private key
		// public and private key are shown to user and stored in appropriate folders
		// file name of both public and private key are the same and use Date.now()
	}

	private static void showPublicKeys(Scanner sc) {
		// displays all public key files
		print("File name: "); // file name of specific public key
		// shows the actual public key in the terminal
	}

	private static void showTransmittedData(Scanner sc) {
		print("Specific public key: "); // shows all messages that are intended for this public key (txt file)
	}

	private static void sendMessage(Scanner sc) {
		print("Message: "); // sender's message
		print("Receiver's public key: "); // intended recipient's public key (txt file)
		print("Sender's private key: "); // private key of sender (txt file)

	}

	private static void readMessage(Scanner sc) {
		print("File name: "); // message receiver wants to read
		print("Receiver's private key"); // private key of receiver (txt file)
		print("Sender's public key"); // public key of sender for verification (txt file)
	}

	private static void print(Object o) {
		System.out.print(o.toString());
	}

}
