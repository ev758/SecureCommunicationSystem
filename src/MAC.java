import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

public class MAC {
    //declarations
    private Mac messageAuthentication;
    private Key messageAuthenticationKey;

    //MAC constructor
    public MAC() {
        try {
            KeyGenerator messageAuthenticationGenerator = KeyGenerator.getInstance("AES");

            //generate random number
            SecureRandom secureRandomNumber = new SecureRandom();

            messageAuthenticationGenerator.init(secureRandomNumber);
            messageAuthenticationKey = messageAuthenticationGenerator.generateKey();

            //generate MAC
            messageAuthentication = Mac.getInstance("HmacSHA256");
            messageAuthentication.init(messageAuthenticationKey);
        }
        catch (NoSuchAlgorithmException error) {
            System.out.println("Error");
        }
        catch (InvalidKeyException error) {
            System.out.println("Error");
        }
    }

    //calculates and gets MAC
    public String macCalculation(String textPar) {
        //declarations
        String messageAuthenticationText = "";
        byte text[];
        byte messageAuthenticationBytes[];

        //bytes of data
        text = textPar.getBytes();

        //MAC
        messageAuthenticationBytes = messageAuthentication.doFinal(text);

        messageAuthenticationText = new String(messageAuthenticationBytes);

        //output
        return messageAuthenticationText;
    }

    //convert String MAC key to MAC key
    public void convertToMessageAuthenticationKey(String messageAuthenticationKeyPar) {
        byte messageAuthenticationKeyByte[] = Base64.getDecoder().decode(messageAuthenticationKeyPar);

        messageAuthenticationKey = new SecretKeySpec(messageAuthenticationKeyByte, 0, messageAuthenticationKeyByte.length, "AES");
    }

    //regenerate MAC with converted MAC key
    public void regenerateMessageAuthentication() {
        try {
            //generate MAC
            messageAuthentication = Mac.getInstance("HmacSHA256");
            messageAuthentication.init(messageAuthenticationKey);
        }
        catch (NoSuchAlgorithmException error) {
            System.out.println("Error");
        }
        catch (InvalidKeyException error) {
            System.out.println("Error");
        }
    }

    //gets MAC key
    public Key getMessageAuthenticationKey() {
        return messageAuthenticationKey;
    }
}
