/**
 * @author Malte Neumann
 *
 */
package keygenerator;

import java.io.*;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import javax.xml.bind.DatatypeConverter;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.openssl.EncryptionException;
import org.bouncycastle.openssl.PEMEncryptor;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.openssl.jcajce.JcePEMEncryptorBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;


public class Keygen {

    private static KeyPair generateRsaKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048, new SecureRandom());
        KeyPair keyPair = keyGen.generateKeyPair();
        
        return keyPair;
    }
    
    /**
     * Erstellt einen RSA-Publickey im Format für SSH.
     * Das Format des SSH-Key ist in RFC #4253 beschrieben. Datentypen sind nach section #5 of RFC #4251 definiert
     *  
     * Code aus diesem Beispiel: http://stackoverflow.com/questions/3706177
     * 
     * @param key
     * @return Binär kodierter öffentlicher Schlüssel im SSH-Format
     */
    private static byte[] encodeSSHPubKey(RSAPublicKey key){
        try {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            //encode the "ssh-rsa" string 
            byte[] sshrsa = new byte[] {0, 0, 0, 7, 's', 's', 'h', '-', 'r', 's', 'a'};
            out.write(sshrsa);
            
            //Encode the public exponent 
            BigInteger e = key.getPublicExponent();
            byte[] data = e.toByteArray();
            byte[] length = encodeUInt32(data.length);
            out.write(length);
            out.write(data);
            
            //Encode the modulus
            BigInteger m = key.getModulus();
            data = m.toByteArray();
            length = encodeUInt32(data.length);
            out.write(length);
            out.write(data);
            return out.toByteArray();
        }
        catch (IOException e) {
            e.printStackTrace();
            // TODO Fehlerbehandlung
            return null;
        }
    }
    
    private static String getSSHkeyString(RSAPublicKey key, String name) {
        byte[] encodedKey = encodeSSHPubKey(key);
        String result = "ssh-rsa " 
                    + DatatypeConverter.printBase64Binary(encodedKey)
                    + " " + name;
        return result;
    }
    
    private static String formatBase64Line(String data) {
        final int lineLength = 64;
        StringBuilder result = new StringBuilder();
        int i = 0;
        while (i*lineLength < data.length()){
            int start = i*lineLength;
            
            String part = data.substring(start, Math.min(start + lineLength, data.length()));
            result.append(part + "\n");
            i++;
        }
        
        return result.toString();
    }
    
    
    public static byte[] encodeUInt32(int value)
    {
        byte[] tmp = new byte[4];
        tmp[0] = (byte)((value >>> 24) & 0xff);
        tmp[1] = (byte)((value >>> 16) & 0xff);
        tmp[2] = (byte)((value >>> 8) & 0xff);
        tmp[3] = (byte)(value & 0xff);
        
        return tmp;
    }

    private static void saveAsPem(RSAPrivateKey privateKey, String password, String cipher) throws IOException {
        File filename;
        PEMEncryptor encryptor;
        if (password != null) {
            filename = new File("private-password_" + password + "-" + cipher + ".pem");
            JcePEMEncryptorBuilder builder = new JcePEMEncryptorBuilder(cipher);
            encryptor = builder.build(password.toCharArray());
        } else {
            filename = new File("private-nopassword-" + cipher + ".pem");
            encryptor = null;
        }
        
        
        try(JcaPEMWriter pemWriter = new JcaPEMWriter(new FileWriter(filename))) {
            pemWriter.writeObject(privateKey, encryptor);
        }
    }
    
    private static void saveToFile(byte[] key, String filename) throws IOException {
        try(FileOutputStream out = new FileOutputStream(filename)) {
            out.write(key);
        }
    }
    
    private static byte[] createCertRequest(KeyPair keypair) throws OperatorCreationException, IOException {
        String sigName = "SHA1withRSA";
        
        X500NameBuilder x500NameBld = new X500NameBuilder(BCStyle.INSTANCE);

        x500NameBld.addRDN(BCStyle.C, "DE");
        x500NameBld.addRDN(BCStyle.O, "Java generated request");
        x500NameBld.addRDN(BCStyle.L, "Mannheim");
        x500NameBld.addRDN(BCStyle.ST, "Baden-Württemberg");
        x500NameBld.addRDN(BCStyle.EmailAddress, "test@hiapo.de");

        X500Name subject = x500NameBld.build();

        PKCS10CertificationRequestBuilder requestBuilder = new JcaPKCS10CertificationRequestBuilder(subject, keypair.getPublic());
                            
        PKCS10CertificationRequest request = requestBuilder.build(new JcaContentSignerBuilder(sigName).build(keypair.getPrivate()));

        return request.getEncoded();
    }
    
    public static void main(String[] args) throws Exception {
        try {
            System.out.println("Generate RSA keypair");
            KeyPair keypair = generateRsaKeyPair();
            
            RSAPublicKey pubKey = (RSAPublicKey) keypair.getPublic();
            RSAPrivateKey privKey = (RSAPrivateKey) keypair.getPrivate();
            
            File file = new File("dummy.txt");
            System.out.println("Directory: " + file.getAbsoluteFile().getParent());
            
            System.out.println("SSH-Publickey codieren");
            String sshPublickeyString = getSSHkeyString(pubKey, "Keyname may be filled");
            System.out.println("Save ssh public");
            saveToFile(sshPublickeyString.getBytes(), "ssh-public.pub");
            
            System.out.println("Save private key in \"" + keypair.getPrivate().getFormat() + "\"-format");
            saveToFile(keypair.getPrivate().getEncoded(), "private-"+ keypair.getPrivate().getFormat() + "-no_encryption.der");
            
            String[] ciphers = {"AES-256-CBC", "AES-256-ECB", "DES-EDE3-CBC"};  
            for (String cipher: ciphers){
                String password = "P@$$word";
                
                System.out.println("Save private key in PEM-Format. Cipher: " + cipher + " password: \"" + password + "\"");
                saveAsPem(privKey, password, cipher);
                
                System.out.println("Save private key in PEM-Format. Cipher: " + cipher + " no password.");
                saveAsPem(privKey, null, cipher);
            }
            
            System.out.println("Generate certificate request");
            byte[] certRequest = createCertRequest(keypair);
            System.out.println("Save cert request");
            saveToFile(certRequest, "certRequest.csr");
            
            String requestBase64 = "-----BEGIN CERTIFICATE REQUEST-----\n" +
                    formatBase64Line(DatatypeConverter.printBase64Binary(certRequest)) +
                    "-----END CERTIFICATE REQUEST-----\n";
            saveToFile(requestBase64.getBytes(), "certRequestBase64.csr");
        } catch (EncryptionException e) {
            System.out.println("Fehler!!!");
            System.out.println("Es fehlt Java Cryptography Extension (JCE):");
            System.out.println("http://www.oracle.com/technetwork/java/javase/downloads/jce-7-download-432124.html");
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }
        
    }

}
