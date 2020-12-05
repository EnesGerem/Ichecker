import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.RandomAccessFile;

import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;

import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.Scanner;

import java.text.SimpleDateFormat;
import java.math.BigInteger;

public class CheckIntegrity {
    private final PublicKey publicKey;

    public CheckIntegrity(HashMap<String,String> arguments)
            throws CertificateException, NoSuchAlgorithmException, IOException,
                   InvalidKeyException, SignatureException {
        //Getting arguments
        String logPath         = arguments.get("log");
        String hashType        = arguments.get("hash");
        String registryPath    = arguments.get("registry");
        String monitoredPath   = arguments.get("path");
        String certificatePath = arguments.get("public");


        //Reading certificate and getting public key from that
        this.publicKey   = readCertificate(certificatePath).getPublicKey();

        //Openning log file with append mode
        PrintWriter log = new PrintWriter(new FileWriter(logPath,true));

        //Scanning through registry file to get monitored files' information but not signature
        String registryContent = scanFile(registryPath);

        //Verifying signature
        boolean signatureVerification = verifySignature(registryContent,hashType,registryPath);
        if (!signatureVerification)
            { log.println(now() + ": Registry file verification failed!"); log.close(); System.exit(1); }

        //Getting files of monitored path
        File[] filesList = new File(monitoredPath).listFiles();

        //Getting the first information of monitored files from registry file
        String[] lines = registryContent.split("\n");

        //Constructing hashmaps holding path and hashed content as key value pair
        HashMap<String,String> pathFiles       = new HashMap<>();
        HashMap<String,String> registeredFiles = new HashMap<>();

        for (File file:filesList) pathFiles.put(file.getPath(),hash(readFile(file.getPath()),hashType));
        for (String line:lines) { String[] record = line.split(" "); registeredFiles.put(record[0],record[1]); }

        //Checking integrity
        boolean isAltered = false;
        boolean isDeleted = false;
        boolean isCreated = false;

        //If a files appearing in monitored path but not in registry file, meaning it's newly created
        for (String pathFilesPath:pathFiles.keySet())
            if (!registeredFiles.containsKey(pathFilesPath))
            { log.println(now()+": "+pathFilesPath+" is created"); isCreated = true; }

        //If a file appearing in registry file but not in monitored file, meaning it's deleted from path
        for (String registeredFilesPath:registeredFiles.keySet())
            if (!pathFiles.containsKey(registeredFilesPath))
            { log.println(now()+": "+registeredFilesPath+" is deleted"); isDeleted = true; }

        //If a file's content in the monitored path is not same as registry saved content, meaning it's altered
        for (String registeredFilePath:registeredFiles.keySet())
            if (pathFiles.get(registeredFilePath) != null)
                if (!registeredFiles.get(registeredFilePath).equals(pathFiles.get(registeredFilePath)))
                { log.println(now()+": "+registeredFilePath+" is altered"); isAltered = true; }

        if (!isAltered && !isCreated && !isDeleted)
            log.println(now()+": The directory is checked and no change is detected!");

        log.close();
    }

    private boolean verifySignature(String registryContent,String hashType,String registryPath)
            throws IOException, NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        //Arranging file pointer to end of monitored files' information to get the beginning of signature
        RandomAccessFile raf = new RandomAccessFile(registryPath, "r");
        raf.seek(registryContent.length()); raf.readLine();

        //Getting all bytes of signature
        ArrayList<Byte> arrayList = new ArrayList<>();

        while(raf.getFilePointer() != raf.length()) arrayList.add(raf.readByte()); raf.close();
        byte[] sign = new byte[arrayList.size()];
        for (int i = 0; i < arrayList.size(); i++) sign[i] = arrayList.get(i);

        //Specifying hash type
        String hash = hashType.equals("SHA-256")?"SHA256":"MD5";

        //Getting signature
        Signature signature = Signature.getInstance(hash+"withRSA");
        signature.initVerify(this.publicKey);
        signature.update(registryContent.getBytes());
        
        //Verifying signature
        boolean isVerified;
        try { isVerified = signature.verify(sign); }
        catch (SignatureException e) { isVerified = false; }

        return isVerified;
    }

    private Certificate readCertificate(String certificatePath) throws CertificateException, IOException{
        //Getting certificate from public certificate file
        return CertificateFactory.getInstance("X.509").generateCertificate(new FileInputStream(certificatePath));
    }

    private static String hash(String content,String hash) throws NoSuchAlgorithmException{
        return new BigInteger(1,MessageDigest.getInstance(hash).digest(content.getBytes())).toString(2);
    }

    private static String readFile(String fileName) throws FileNotFoundException{
        //Reading a file
        StringBuilder fileContent = new StringBuilder();
        Scanner file = new Scanner(new File(fileName));

        while(file.hasNext()) fileContent.append(file.nextLine());

        file.close();
        return fileContent.toString();
    }

    private static String scanFile(String fileName) throws IOException {
        StringBuilder fileContent = new StringBuilder();
        BufferedReader bf = new BufferedReader(new FileReader(fileName));

        while (true) { String line = bf.readLine(); if (line.equals("SIGNATURE")) break; fileContent.append(line+"\n"); }
        bf.close();

        return fileContent.toString();
    }

    private static String now(){ return new SimpleDateFormat("dd-MM-yyyy HH:mm:ss").format(new Date()); }

}
