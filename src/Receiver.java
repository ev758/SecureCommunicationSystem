import java.io.File;
import java.io.FileNotFoundException;
import java.util.Scanner;

public class Receiver {

    public static void main(String[] args) {
        //declarations
        String transmittedDataText[] = new String[2];
        String transmittedDataTexts = "";
        String transmittedDataMac = "";
        String receiverPrivateKey = "";
        String messageAuthenticationKey = "";
        RSAReceiverKeyPairs receiverKeyPairs = new RSAReceiverKeyPairs();
        AESKey aesKey = new AESKey();
        String aesKeyInput = "";
        MAC messageAuthentication = new MAC();
        String messageAuthenticationText = "";
        int i = 0;

        try {
            //declarations
            File transmittedDataFile = new File(System.getProperty("user.dir") + "\\src\\Transmitted_Data\\Transmitted_Data.txt");
            Scanner transmittedData = new Scanner(transmittedDataFile);
            File receiverPrivateKeyFile = new File(System.getProperty("user.dir") + "\\src\\receiver_key_pairs\\receiver_private_key.txt");
            Scanner receiverPrivateKeyInput = new Scanner(receiverPrivateKeyFile);
            File messageAuthenticationKeyTextFile = new File(System.getProperty("user.dir") + "\\src\\mac_key.txt");
            Scanner messageAuthenticationKeyTextFileInput = new Scanner(messageAuthenticationKeyTextFile);

            //gets String private key of receiver
            receiverPrivateKey = receiverPrivateKeyInput.nextLine();

            //gets String MAC key
            messageAuthenticationKey = messageAuthenticationKeyTextFileInput.nextLine();

            //gets transmitted data texts
            while (transmittedData.hasNextLine()) {
                if (i == 2) {
                    //gets sender MAC
                    transmittedDataMac = transmittedData.nextLine();
                    break;
                }
                else {
                    //gets encrypted message and encrypted AES key
                    transmittedDataText[i] = transmittedData.nextLine();
                    i++;
                }
            }

            transmittedDataTexts = transmittedDataText[0] + "\n" + transmittedDataText[1];

            //convert String MAC key to MAC key, and regenerate MAC to calculate receiver's MAC
            messageAuthentication.convertToMessageAuthenticationKey(messageAuthenticationKey);
            messageAuthentication.regenerateMessageAuthentication();

            //receiver MAC
            messageAuthenticationText = messageAuthentication.macCalculation(transmittedDataTexts);

            //displays sender MAC and receiver MAC
            System.out.println("Sender MAC: " + transmittedDataMac + "\n");
            System.out.println("Receiver MAC: " + messageAuthenticationText + "\n");

            //if sender mac and receiver MAC are equal, message authenticated and display decrypted message
            //if sender mac and receiver MAC are not equal, message not authenticated
            if (transmittedDataMac.equals(messageAuthenticationText)) {
                System.out.println("Message Authenticated" + "\n");

                //convert String private key of receiver to PrivateKey
                receiverKeyPairs.convertToPrivateKey(receiverPrivateKey);

                //decrypts encrypted AES key
                aesKeyInput = receiverKeyPairs.rsaDecryption(transmittedDataText[1]);

                //convert String AES key to AES key
                aesKey.convertToAesKey(aesKeyInput);
                System.out.print("Message decrypted: " + aesKey.aesDecryption(transmittedDataText[0], aesKey.getAesKey()));
            }
            else {
                System.out.print("Message Not Authenticated");
            }

            transmittedData.close();
            receiverPrivateKeyInput.close();
            messageAuthenticationKeyTextFileInput.close();
        }
        catch (FileNotFoundException fileError) {
            System.out.println("File not found");
        }
        catch (Exception error) {
            System.out.println("Error");
        }
    }
}
