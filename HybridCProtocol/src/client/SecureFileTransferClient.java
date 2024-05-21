package client;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.Socket;
import java.nio.file.Files;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Scanner;
import java.util.Base64;

public class SecureFileTransferClient {
    private static final String SERVER_ADDRESS = "localhost";
    private static final int SERVER_PORT = 12345;
    private static final String RSA_ALGORITHM = "RSA";
    private static final String AES_ALGORITHM = "AES";
    private static final String SIGN_ALGORITHM = "SHA256withRSA";
    private KeyPair rsaKeyPair;
    private PrivateKey privateKey;
    private PublicKey publicKey;
    private PublicKey serverPublicKey;

    public SecureFileTransferClient() throws Exception {
        // Generate RSA key pair
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(RSA_ALGORITHM);
        keyGen.initialize(2048);
        rsaKeyPair = keyGen.generateKeyPair();
        privateKey = rsaKeyPair.getPrivate();
        publicKey = rsaKeyPair.getPublic();
    }

    public void connectAndTransferFile(String filePath) throws Exception {
        try (Socket socket = new Socket(SERVER_ADDRESS, SERVER_PORT)) {
            DataInputStream input = new DataInputStream(socket.getInputStream());
            DataOutputStream output = new DataOutputStream(socket.getOutputStream());

            // Receive server's public key
            int length = input.readInt();
            byte[] serverPublicKeyBytes = new byte[length];
            input.readFully(serverPublicKeyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance(RSA_ALGORITHM);
            serverPublicKey = keyFactory.generatePublic(new X509EncodedKeySpec(serverPublicKeyBytes));

            // Send client's public key
            output.writeInt(publicKey.getEncoded().length);
            output.write(publicKey.getEncoded());

            // Generate AES key
            KeyGenerator keyGen = KeyGenerator.getInstance(AES_ALGORITHM);
            keyGen.init(256);
            SecretKey aesKey = keyGen.generateKey();

            // Encrypt AES key with server's public key
            Cipher rsaCipher = Cipher.getInstance(RSA_ALGORITHM);
            rsaCipher.init(Cipher.ENCRYPT_MODE, serverPublicKey);
            byte[] encryptedAesKey = rsaCipher.doFinal(aesKey.getEncoded());
            output.writeInt(encryptedAesKey.length);
            output.write(encryptedAesKey);

            // Read file data
            File file = new File(filePath);
            byte[] fileData = Files.readAllBytes(file.toPath());

            // Encrypt file data
            Cipher aesCipher = Cipher.getInstance(AES_ALGORITHM);
            aesCipher.init(Cipher.ENCRYPT_MODE, aesKey);
            byte[] encryptedFileData = aesCipher.doFinal(fileData);

            // Print the encrypted file content (for debugging purposes)
            System.out.println("Encrypted File Data: " + Base64.getEncoder().encodeToString(encryptedFileData));

            // Generate file hash
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] fileHash = digest.digest(fileData);

            // Sign the file hash
            Signature sig = Signature.getInstance(SIGN_ALGORITHM);
            sig.initSign(privateKey);
            sig.update(fileHash);
            byte[] fileSignature = sig.sign();

            // Send file name, signature, and data
            output.writeUTF(file.getName());
            output.writeInt(fileSignature.length);
            output.write(fileSignature);
            output.writeInt(encryptedFileData.length);
            output.write(encryptedFileData);
            System.out.println("File '" + file.getName() + "' encrypted and sent successfully.");
        }
    }


    public static void main(String[] args) throws Exception {
        SecureFileTransferClient client = new SecureFileTransferClient();

        Scanner scanner = new Scanner(System.in);
        System.out.println("Enter file path for transfer: ");
        String filePath = scanner.nextLine();

        client.connectAndTransferFile(filePath);
    }

}
