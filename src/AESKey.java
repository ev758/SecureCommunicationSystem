import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class AESKey {
    //declarations
    private SecretKey aesKey;

    //AES key constructor
    public AESKey() {
        try {
            //generate AES key
            KeyGenerator aesKeyGenerator = KeyGenerator.getInstance("AES");

            aesKeyGenerator.init(128);

            aesKey = aesKeyGenerator.generateKey();
        }
        catch (NoSuchAlgorithmException error) {
            System.out.println("Error");
        }
    }

    //encrypts text with AES encryption
    public String aesEncryption(String textPar) throws Exception {
        //declarations
        byte text[];
        byte aesCipher[];

        //bytes of data
        text = textPar.getBytes();

        //encryption
        Cipher plaintextEncryption = Cipher.getInstance("AES");

        plaintextEncryption.init(Cipher.ENCRYPT_MODE, aesKey);

        aesCipher = plaintextEncryption.doFinal(text);

        //output
        return Base64.getEncoder().encodeToString(aesCipher);
    }

    //decrypts text with AES decryption
    public String aesDecryption(String textPar, SecretKey aesKeyPar) throws Exception {
        //declarations
        String plaintext;
        byte cipherDecryption[];
        byte plaintextBytes[];

        cipherDecryption = Base64.getDecoder().decode(textPar);

        //decryption
        Cipher plaintextDecryption = Cipher.getInstance("AES");

        plaintextDecryption.init(Cipher.DECRYPT_MODE, aesKeyPar);

        plaintextBytes = plaintextDecryption.doFinal(cipherDecryption);

        plaintext = new String(plaintextBytes, StandardCharsets.UTF_8);

        //output
        return plaintext;
    }

    //convert String AES key to AES key
    public void convertToAesKey(String aesKeyPar) {
        byte aesKeyByte[] = Base64.getDecoder().decode(aesKeyPar);

        aesKey = new SecretKeySpec(aesKeyByte, 0, aesKeyByte.length, "AES");
    }

    //gets AES key
    public SecretKey getAesKey() {
        return aesKey;
    }
}
