import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import java.io.FileInputStream;
import java.io.FileWriter;
import java.io.IOException;

import java.nio.file.FileSystems;
import java.nio.file.Files;

import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.spec.PKCS8EncodedKeySpec;

import java.util.Enumeration;
import java.util.HashMap;
import java.util.Scanner;

public class CreateCertification {
    public CreateCertification(HashMap<String,String> arguments)
            throws UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException,
                   IOException, InvalidKeyException, BadPaddingException,
                   NoSuchPaddingException, IllegalBlockSizeException, CertificateException {
        //Getting arguments
        String pubkey = arguments.get("public");
        String prikey = arguments.get("private");

        //Getting keypair
        KeyPair keyPair = generateKeyPair();

        //Storing private key
        storePrivateFile(keyPair,prikey);

        //Storing public certificate
        generateCertificate(pubkey);
    }

    private KeyPair generateKeyPair() throws IOException, KeyStoreException, UnrecoverableKeyException, NoSuchAlgorithmException, CertificateException {
        //Deleting keypair file if exists because it prevents the execution of command
        Files.deleteIfExists(FileSystems.getDefault().getPath("keypair.p12"));

        //Generating a keypair
        execute(" -genkeypair"+
                " -alias keypair"+
                " -keysize 2048"+
                " -keyalg RSA"+
                " -sigalg SHA256withRSA"+
                " -dname CN=ENES"+
                " -storetype PKCS12"+
                " -keystore keypair.p12"+
                " -keypass password"+
                " -storepass password");

        //Getting keystore object from generated keypair
        FileInputStream is = new FileInputStream("keypair.p12");
        KeyStore keystore = KeyStore.getInstance("PKCS12");
        keystore.load(is, "password".toCharArray());

        //Getting alias of keystore
        Enumeration<String> enumeration = keystore.aliases();
        String alias = enumeration.nextElement();

        //Getting privatekey from keystore
        PrivateKey privateKey = (PrivateKey) keystore.getKey(alias, "password".toCharArray());

        //Getting public key from x.509 certificate of keystore
        PublicKey publicKey = keystore.getCertificate(alias).getPublicKey();

        //Returning a key pair
        return new KeyPair(publicKey, privateKey);
    }

    private void generateCertificate(String certificatePath) throws IOException {
        //Generating a Certificate Signing Request
        execute("-certreq"      +
                " -alias keypair"        +
                " -dname CN=ENES"        +
                " -storetype PKCS12"     +
                " -keypass password"     +
                " -file request.csr"     +
                " -storepass password"   +
                " -keystore keypair.p12" +
                " -sigalg SHA256withRSA" );

        //Generating X.509 public certificate
        execute("-gencert"      +
                " -rfc"                  +
                " -validity 365"         +
                " -dname CN=ENES"        +
                " -alias keypair"        +
                " -keypass password"     +
                " -storetype PKCS12"     +
                " -infile request.csr"   +
                " -storepass password"   +
                " -keystore keypair.p12" +
                " -sigalg SHA256withRSA" +
                " -outfile " + certificatePath );

        //Deleting keypair and request files, there are not needed anymore
        Files.deleteIfExists(FileSystems.getDefault().getPath("keypair.p12"));
        Files.deleteIfExists(FileSystems.getDefault().getPath("request.csr"));
    }

    private void execute(String command){
        try{ sun.security.tools.keytool.Main.main(command.trim().split("\\s+")); }
        catch (Exception e) { e.printStackTrace(); }
    }

    private void storePrivateFile(KeyPair keyPair,String path)
            throws IOException, NoSuchAlgorithmException, IllegalBlockSizeException,
                   InvalidKeyException, NoSuchPaddingException, BadPaddingException {
        //Getting private key information
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(keyPair.getPrivate().getEncoded());

        //Concatenating private key information and additional information
        byte[] additional = "This is private key file".getBytes();
        byte[] privateKeyInfo = pkcs8EncodedKeySpec.getEncoded();
        byte[] plaintext = new byte[additional.length+privateKeyInfo.length];

        System.arraycopy(privateKeyInfo,0,plaintext,0,privateKeyInfo.length);
        System.arraycopy(additional,0,plaintext,privateKeyInfo.length,additional.length);

        //Getting a password from user to make it AES key
        System.out.print("Enter a password: ");
        Scanner askPassword = new Scanner(System.in);
        String password = askPassword.nextLine(); askPassword.close();

        //Converting entered password to binary format and padding with "10"
        password = convertStringToBinary(password);
        while(password.length() < 256) password += "10";

        //Encrypting private key and additional information with hashed password key
        AES aes = new AES(MessageDigest.getInstance("MD5").digest(password.getBytes()));

        //Storing private key file
        FileWriter prikeyFile = new FileWriter(path);
        prikeyFile.write(new String(aes.encrypt(plaintext))); prikeyFile.close();
    }

    private String convertStringToBinary(String input) {
        StringBuilder result = new StringBuilder();
        char[] chars = input.toCharArray();

        for (char aChar : chars)
            result.append(String.format("%8s", Integer.toBinaryString(aChar)).replaceAll(" ", "0"));

        return result.toString();
    }
}
