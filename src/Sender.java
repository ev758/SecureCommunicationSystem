import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.Base64;
import java.util.Scanner;

public class Sender {

    public static void main(String[] args) {
        //declarations
        RSASenderKeyPairs rsaSenderKeyPairs = new RSASenderKeyPairs();
        RSAReceiverKeyPairs rsaReceiverKeyPairs = new RSAReceiverKeyPairs();
        AESKey aesKey = new AESKey();
        MAC messageAuthentication = new MAC();
        String messageAuthenticationText = "";
        String encryptedAesKey = "";
        String transmittedDataTexts = "";

        try {
            //declarations
            String senderPublicKey = System.getProperty("user.dir");
            String senderPrivateKey = System.getProperty("user.dir");
            String receiverPublicKey = System.getProperty("user.dir");
            String receiverPrivateKey = System.getProperty("user.dir");
            String transmittedData = System.getProperty("user.dir");
            String messageAuthenticationKey = System.getProperty("user.dir");
            File plaintextFile = new File(System.getProperty("user.dir") + "\\src\\plaintext.txt");
            Scanner input = new Scanner(plaintextFile);

            //sender public and private key stored in sender_key_pairs folder as text files
            senderPublicKey = senderPublicKey + "\\src\\sender_key_pairs\\sender_public_key.txt";
            senderPrivateKey = senderPrivateKey + "\\src\\sender_key_pairs\\sender_private_key.txt";

            //receiver public and private key stored in receiver_key_pairs folder as text files
            receiverPublicKey = receiverPublicKey + "\\src\\receiver_key_pairs\\receiver_public_key.txt";
            receiverPrivateKey = receiverPrivateKey + "\\src\\receiver_key_pairs\\receiver_private_key.txt";

            //transmitted data of encrypted message, encrypted AES key, and MAC stored in Transmitted_Data folder as text file
            transmittedData = transmittedData + "\\src\\Transmitted_Data\\Transmitted_Data.txt";

            //MAC key stored as text file
            messageAuthenticationKey = messageAuthenticationKey + "\\src\\mac_key.txt";

            //sender public and private key written as text files in sender_key_pairs folder
            FileWriter writeSenderPublicKeyFile = new FileWriter(senderPublicKey);
            writeSenderPublicKeyFile.write(Base64.getEncoder().encodeToString(rsaSenderKeyPairs.senderPublicKey().getEncoded()));

            FileWriter writeSenderPrivateKeyFile = new FileWriter(senderPrivateKey);
            writeSenderPrivateKeyFile.write(Base64.getEncoder().encodeToString(rsaSenderKeyPairs.senderPrivateKey().getEncoded()));

            //receiver public and private key written as text files in receiver_key_pairs folder
            FileWriter writeReceiverPublicKeyFile = new FileWriter(receiverPublicKey);
            writeReceiverPublicKeyFile.write(Base64.getEncoder().encodeToString(rsaReceiverKeyPairs.receiverPublicKey().getEncoded()));

            FileWriter writeReceiverPrivateKeyFile = new FileWriter(receiverPrivateKey);
            writeReceiverPrivateKeyFile.write(Base64.getEncoder().encodeToString(rsaReceiverKeyPairs.receiverPrivateKey().getEncoded()));

            //MAC key written as text file
            FileWriter messageAuthenticationKeyTextFile = new FileWriter(messageAuthenticationKey);
            messageAuthenticationKeyTextFile.write(Base64.getEncoder().encodeToString(messageAuthentication.getMessageAuthenticationKey().getEncoded()));

            //gets message
            String plaintext = input.nextLine();

            //encrypted message
            String ciphertext = aesKey.aesEncryption(plaintext);
            System.out.println("Encrypted message: " + ciphertext);
            System.out.print("\n");

            //encrypted AES key
            encryptedAesKey = rsaReceiverKeyPairs.rsaEncryption(Base64.getEncoder().encodeToString(aesKey.getAesKey().getEncoded()));
            System.out.print("Encrypted AES key: " + encryptedAesKey);

            //sender MAC
            messageAuthenticationText = messageAuthentication.macCalculation(ciphertext + "\n" + encryptedAesKey);

            //transmitted data written as text file in Transmitted_Data folder
            FileWriter writeTransmittedDataFile = new FileWriter(transmittedData);

            transmittedDataTexts = ciphertext + "\n" + encryptedAesKey + "\n" + messageAuthenticationText;

            writeTransmittedDataFile.write(transmittedDataTexts);

            writeSenderPublicKeyFile.close();
            writeSenderPrivateKeyFile.close();
            writeReceiverPublicKeyFile.close();
            writeReceiverPrivateKeyFile.close();
            writeTransmittedDataFile.close();
            messageAuthenticationKeyTextFile.close();
            input.close();
        }
        catch (IOException error) {
            System.out.println("Error");
        }
        catch (Exception error) {
            System.out.println("Error");
        }
    }
}
