import javax.crypto.Cipher;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class RSASenderKeyPairs {
    //declarations
    private PublicKey senderRsaPublicKey;
    private PrivateKey senderRsaPrivateKey;

    //RSA sender key pairs constructor
    public RSASenderKeyPairs() {
        try {
            //generate RSA key pair
            KeyPairGenerator senderRsaKeyPairGenerator = KeyPairGenerator.getInstance("RSA");

            senderRsaKeyPairGenerator.initialize(1024);

            KeyPair senderRsaKeyPair = senderRsaKeyPairGenerator.generateKeyPair();

            //sender's RSA public and private key
            senderRsaPublicKey = senderRsaKeyPair.getPublic();

            senderRsaPrivateKey = senderRsaKeyPair.getPrivate();
        }
        catch (NoSuchAlgorithmException error) {
            System.out.println("Error");
        }
    }

    //encrypts text with sender's RSA public key
    public String rsaEncryption(String textPar) throws Exception {
        //declarations
        byte text[];
        byte rsaCipher[];

        //bytes of data
        text = textPar.getBytes();

        //encryption
        Cipher plaintextEncryption = Cipher.getInstance("RSA");

        plaintextEncryption.init(Cipher.ENCRYPT_MODE, senderRsaPublicKey);

        rsaCipher = plaintextEncryption.doFinal(text);

        //output
        return Base64.getEncoder().encodeToString(rsaCipher);
    }

    //decrypts text with sender's RSA private key
    public String rsaDecryption(String textPar) throws Exception {
        //declarations
        String plaintext;
        byte cipherDecryption[];
        byte plaintextBytes[];

        cipherDecryption = Base64.getDecoder().decode(textPar);

        //decryption
        Cipher plaintextDecryption = Cipher.getInstance("RSA");

        plaintextDecryption.init(Cipher.DECRYPT_MODE, senderRsaPrivateKey);

        plaintextBytes = plaintextDecryption.doFinal(cipherDecryption);

        plaintext = new String(plaintextBytes, StandardCharsets.UTF_8);

        //output
        return plaintext;
    }

    //gets sender's RSA public key
    public PublicKey senderPublicKey() {
        return senderRsaPublicKey;
    }

    //gets sender's RSA private key
    public PrivateKey senderPrivateKey() {
        return senderRsaPrivateKey;
    }
}
