import javax.crypto.Cipher;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

public class RSAReceiverKeyPairs {
    //declarations
    private PublicKey receiverRsaPublicKey;
    private PrivateKey receiverRsaPrivateKey;

    //RSA receiver key pairs constructor
    public RSAReceiverKeyPairs() {
        try {
            //generate RSA key pair
            KeyPairGenerator receiverRsaKeyPairGenerator = KeyPairGenerator.getInstance("RSA");

            receiverRsaKeyPairGenerator.initialize(1024);

            KeyPair receiverRsaKeyPair = receiverRsaKeyPairGenerator.generateKeyPair();

            //receiver's RSA public and private key
            receiverRsaPublicKey = receiverRsaKeyPair.getPublic();

            receiverRsaPrivateKey = receiverRsaKeyPair.getPrivate();
        }
        catch (NoSuchAlgorithmException error) {
            System.out.println("Error");
        }
    }

    //encrypts text with receiver's RSA public key
    public String rsaEncryption(String textPar) throws Exception {
        //declarations
        byte text[];
        byte rsaCipher[];

        //bytes of data
        text = textPar.getBytes();

        //encryption
        Cipher plaintextEncryption = Cipher.getInstance("RSA");

        plaintextEncryption.init(Cipher.ENCRYPT_MODE, receiverRsaPublicKey);

        rsaCipher = plaintextEncryption.doFinal(text);

        //output
        return Base64.getEncoder().encodeToString(rsaCipher);
    }

    //decrypts text with receiver's RSA private key
    public String rsaDecryption(String textPar) throws Exception {
        //declarations
        String plaintext;
        byte cipherDecryption[];
        byte plaintextBytes[];

        cipherDecryption = Base64.getDecoder().decode(textPar);

        //decryption
        Cipher plaintextDecryption = Cipher.getInstance("RSA");

        plaintextDecryption.init(Cipher.DECRYPT_MODE, receiverRsaPrivateKey);

        plaintextBytes = plaintextDecryption.doFinal(cipherDecryption);

        plaintext = new String(plaintextBytes, StandardCharsets.UTF_8);

        //output
        return plaintext;
    }

    //convert String private key of receiver to PrivateKey
    public void convertToPrivateKey(String receiverPrivateKeyPar) {
        try {
            PKCS8EncodedKeySpec receiverPrivateKey = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(receiverPrivateKeyPar));

            KeyFactory privateKeyConvert = KeyFactory.getInstance("RSA");
            receiverRsaPrivateKey = privateKeyConvert.generatePrivate(receiverPrivateKey);
        }
        catch (NoSuchAlgorithmException error) {
            System.out.println("Error");
        }
        catch (InvalidKeySpecException error) {
            System.out.println("Error");
        }
    }

    //gets receiver's RSA public key
    public PublicKey receiverPublicKey() {
        return receiverRsaPublicKey;
    }

    //gets receiver's RSA private key
    public PrivateKey receiverPrivateKey() {
        return receiverRsaPrivateKey;
    }
}
