import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.File;
import java.io.FileNotFoundException;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;

import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

import java.util.Date;
import java.util.HashMap;
import java.util.Scanner;

import java.text.SimpleDateFormat;
import java.math.BigInteger;

public class CreateRegistry {
    private final PrivateKey privateKey;

    public CreateRegistry(HashMap<String,String> arguments)
            throws IOException, NoSuchAlgorithmException, InvalidKeyException,
                   InvalidKeySpecException, SignatureException, NoSuchPaddingException,
                   IllegalBlockSizeException {

        //Getting arguments
        String logPath       = arguments.get("log");
        String hashType      = arguments.get("hash");
        String prikeyPath    = arguments.get("private");
        String registryPath  = arguments.get("registry");
        String monitoredPath = arguments.get("path");

        //Openning log file with append mode
        PrintWriter log = new PrintWriter(new FileWriter(logPath,true));

        //Getting private key information if asked password is correct; password verification is in the function
        this.privateKey = loadPrivateKey(log,prikeyPath);

        //Openning registry file
        PrintWriter registry = new PrintWriter(new BufferedWriter(new FileWriter(registryPath)));
        log.println(now()+": Registry file is created at "+registryPath);

        //Getting files of monitored path
        File[] filesList = new File(monitoredPath).listFiles();

        //Hashing content of all files and storing them into registry file
        StringBuilder registryContent = new StringBuilder();

        for (File file:filesList) {
            registryContent.append(file.getPath()+" "+hash(readFile(file.getPath()),hashType)+"\n");
            log.println(now()+": "+file.getPath()+" is added to registry.");
        }   log.println(now()+": "+filesList.length+
                             " files are added to the registry and registry creation is finished.");

        //Writing information of all monitored files' information into registry
        registry.print(registryContent.toString()+"SIGNATURE\n");

        //Generating signature of registry file and adding it to end of the file
        byte[] signature = signature(registryContent, hashType);
        registry.close(); log.close();
        Files.write(Paths.get(registryPath),signature, StandardOpenOption.APPEND);
    }

    private PrivateKey loadPrivateKey(PrintWriter log, String prikeyPath)
            throws InvalidKeySpecException, NoSuchAlgorithmException, IOException,
                   IllegalBlockSizeException, InvalidKeyException, NoSuchPaddingException {
        //Getting password from user
        System.out.print("Enter your password: ");
        Scanner askPassword = new Scanner(System.in);
        String password = askPassword.nextLine(); askPassword.close();

        //Converting entered password to binary format and padding with "10"
        password = convertStringToBinary(password);
        while(password.length() < 256) password += "10";

        //Sending the key created with entered password to AES
        AES aes = new AES(MessageDigest.getInstance("MD5").digest(password.getBytes()));

        //Reading private key file
        byte[] ciphertext = Files.readAllBytes(Paths.get(prikeyPath));

        //Decrypting private key file
        byte[] plaintext = null;
        try {plaintext = aes.decrypt(ciphertext);} catch (BadPaddingException e)
            { log.println(now()+": Wrong password attempt!"); log.close(); System.exit(1); }

        //Getting private key and additional information part from decrypted private key file
        byte[] additional = "This is private key file".getBytes();
        int prikeyinfoend = plaintext.length - additional.length;

        byte[] privateKeyInfo = new byte[prikeyinfoend];
        byte[] additionalCheck = new byte[additional.length];

        System.arraycopy(plaintext,0,privateKeyInfo,0,prikeyinfoend);
        System.arraycopy(plaintext,prikeyinfoend,additionalCheck,0,additional.length);

        //Checking additional information to verify entered password
        if (!new String(additionalCheck).equals("This is private key file"))
            { log.println(now()+": Wrong password attempt!"); log.close(); System.exit(1); }

        //Returning private key as object
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyInfo);

        return keyFactory.generatePrivate(privateKeySpec);
    }

    private byte[] signature(StringBuilder registryContent, String hashType)
            throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {

        //Specifying hash type
        String hash = hashType.equals("SHA-256")?"SHA256":"MD5";

        //Generating signature with the private key
        Signature signature = Signature.getInstance(hash+"withRSA");
        signature.initSign(this.privateKey);
        signature.update(registryContent.toString().getBytes());

        return signature.sign();
    }

    private String hash(String content,String hash) throws NoSuchAlgorithmException{
        return new BigInteger(1, MessageDigest.getInstance(hash).digest(content.getBytes())).toString(2);
    }

    private String now() { return new SimpleDateFormat("dd-MM-yyyy HH:mm:ss").format(new Date()); }

    private String convertStringToBinary(String input) {
        StringBuilder result = new StringBuilder();
        char[] chars = input.toCharArray();

        for (char aChar : chars)
            result.append(String.format("%8s", Integer.toBinaryString(aChar)).replaceAll(" ", "0"));

        return result.toString();
    }

    private String readFile(String fileName) throws FileNotFoundException{
        StringBuilder fileContent = new StringBuilder();
        Scanner file = new Scanner(new File(fileName));

        while(file.hasNext()) fileContent.append(file.nextLine());

        file.close();
        return fileContent.toString();
    }
}
