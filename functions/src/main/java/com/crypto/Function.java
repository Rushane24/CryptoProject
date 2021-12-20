package com.crypto;

import com.microsoft.azure.functions.ExecutionContext;
import com.microsoft.azure.functions.HttpMethod;
import com.microsoft.azure.functions.HttpRequestMessage;
import com.microsoft.azure.functions.HttpResponseMessage;
import com.microsoft.azure.functions.HttpStatus;
import com.microsoft.azure.functions.annotation.AuthorizationLevel;
import com.microsoft.azure.functions.annotation.FunctionName;
import com.microsoft.azure.functions.annotation.HttpTrigger;

import java.util.Optional;
import java.util.Base64;
import java.io.*;
import static java.nio.charset.StandardCharsets.UTF_8;
import java.security.NoSuchAlgorithmException;
import java.net.*;
import java.util.*;

import javax.crypto.KeyGenerator;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import static java.nio.charset.StandardCharsets.US_ASCII;

/**
 * Azure Functions with HTTP Trigger.
 */

public class Function {
    /**
     * This function listens at endpoint "/api/HttpExample". Two ways to invoke it
     * using "curl" command in bash:
     * 1. curl -d "HTTP Body" {your host}/api/HttpExample
     * 2. curl "{your host}/api/HttpExample?name=HTTP%20Query"
     */
    @FunctionName("HttpExample")
    public HttpResponseMessage run(
            @HttpTrigger(name = "req", methods = { HttpMethod.GET,
                    HttpMethod.POST }, authLevel = AuthorizationLevel.ANONYMOUS) HttpRequestMessage<Optional<String>> request,
            final ExecutionContext context) {
        context.getLogger().info("Java HTTP trigger processed a request.");

        // Parse query parameter
        final String query = request.getQueryParameters().get("name");
        final String name = request.getBody().orElse(query);

        if (name == null) {
            return request.createResponseBuilder(HttpStatus.BAD_REQUEST)
                    .body("Please pass a name on the query string or in the request body").build();
        } else {
            if (name.equals("index")) {
                return request.createResponseBuilder(HttpStatus.OK).header("Content-type", "text/html")
                        .body(renderWebpage("index2.html")).build();
            }
            if (name.equals("password")) {
                {
                    return request.createResponseBuilder(HttpStatus.OK).header("Content-type", "text/html")
                            .body(renderWebpage("cryto_PASSWORD.html")).build();
                }
            }
            if (name.equals("encrypt")) {
                {
                    return request.createResponseBuilder(HttpStatus.OK).header("Content-type", "text/html")
                            .body(renderWebpage("cryto_ENC.html")).build();
                }
            }
            if (name.equals("encryptOP")) {
                {
                    String k1 = request.getQueryParameters().get("size");
                    String k2 = request.getBody().orElse(k1);
                    int size = Integer.parseInt(k2);
                    System.out.println(size);
                    PassGen ob = new PassGen();
                    String psk = ob.generatePassword(size);
                    String htmlcode = renderWebpage("cryto_ENC_OP.html");
                    htmlcode = htmlcode.replace("{{password}}", psk);
                    KeyGen key = new KeyGen();
                    String kk = key.generateKey();
                    htmlcode = htmlcode.replace("{{key}}", kk);
                    String encrtxt = Aes256.encrypt(psk, kk);
                    htmlcode = htmlcode.replace("{{encrtxt}}", encrtxt);
                    return request.createResponseBuilder(HttpStatus.OK).header("Content-type", "text/html")
                            .body(htmlcode).build();
                }
            }
            if (name.equals("decrypt")) {
                {
                    return request.createResponseBuilder(HttpStatus.OK).header("Content-type", "text/html")
                            .body(renderWebpage("cryto_dec.html")).build();
                }
            }
            if (name.equals("decryptOP")) {
                {
                    String cipher = request.getBody().orElse(request.getQueryParameters().get("cipher"));
                    String key = request.getBody().orElse(request.getQueryParameters().get("key"));
                    String clrtxt = Aes256.decrypt(cipher, key);

                    return request.createResponseBuilder(HttpStatus.OK).header("Content-type", "text/html")
                            .body(renderWebpage("cryto_dec_op.html").replace("{{decoutput}}", clrtxt)).build();
                }
            }

            // if(name.equals("password"))
            {
                {
                    return request.createResponseBuilder(HttpStatus.OK).header("Content-type", "text/html")
                            .body(renderWebpage("index2.html")).build();
                }
            }
        }
    }

    public String renderWebpage(String fln) {
        String repo = "https://rushane24.github.io/CryptoProject/";
        try {
            URL url = new URL(repo + fln);
            BufferedReader br = new BufferedReader(new InputStreamReader((url.openStream())));
            String ln = "";
            String k = "";
            while ((ln = br.readLine()) != null) {
                k += ln + "\n";
            }
            k = k.replace("crytography.css", repo + "crytography.css");
            return k;
        } catch (Exception excep) {
            return "Page render error";
        }
    }
}

class Aes256 extends AbstractAes256 {
    /**
     * Encrypt text in String with the passphrase
     * Input text to encrypt
     * A base64 encoded string containing the enrypted data
     * Throws exceptions
     * @Base64.getEncoder()->This class implements an encoder for
     * encoding byte data using the Base64 encoding scheme
     * 
     * @encodeToString()->Encodes the specified byte array into a String
     * @UTF_8->Is used for Variable width Character Encoding
     *            UTF stands for Unicode Transformation Format
     * @getBytes()->method encodes a String into a sequence of bytes and
     *                     returns a byte array.
     */
    public static String encrypt(String input, String passphrase) {
        try {
            return Base64.getEncoder().encodeToString(_encrypt(input.getBytes(UTF_8), passphrase.getBytes(UTF_8)));
        } catch (Exception ex) {
            return "";
        }
        /**
         * This Method is used to Encode the Strong Password generated by the PassGen
         * class
         * into String from byte[] encrypt.
         */
    }

    /**
     * Encrypt text in byte[] Array with the byte[] passphrase
     * Input text to encrypted text
     * A base64 encoded string containing the enrypted data
     * Throws exception
     * 
     * @encode->Encodes the specified byte array input into encrypted byte array
     */
    public static byte[] encrypt(byte[] input, byte[] passphrase) throws Exception {
        return Base64.getEncoder().encode(_encrypt(input, passphrase));
        /**
         * This Method is used to Encode the Strong Password generated by the PassGen
         * class
         * into byte[] array
         */
    }

    /**
     * Decrypt encrypted base64 encoded text in bytes to String
     * Crypted text in bytes to decrypted String
     * The passphrase is in bytes
     * Decrypted data in String is returned
     * Throws exceptions
     * 
     * @Decode->Decodes the specified crypted byte array input
     *                  into decrypted String
     *                  @Base64.getDecoder()->This class implements a Decoder for
     *                  Decoding byte data into string using the Base64 encoding
     *                  scheme
     * @DecodeToString()->Decodes the specified byte array into a String
     */
    public static String decrypt(String crypted, String passphrase) {
        try {
            return new String(_decrypt(Base64.getDecoder().decode(crypted), passphrase.getBytes(UTF_8)), UTF_8);
        } catch (Exception excep) {
            return "";
        }
        /**
         * This method takes the input from the byte[] decrypt and decryptes
         * the bytes into a String to return a Decoded cryptic text i.e the initial
         * value that we passed as input to encrypt the password.
         */
    }

    /**
     * Decrypt encrypted base64 encoded text in bytes
     * Crypted Text in bytes to decrypt
     * The passphrase in bytes
     * Return Decrypted data in bytes
     * Throws exceptions
     * 
     * @Decode->Decodes the specified encryptes byte array input into Decrypted byte
     *                  array
     */
    public static byte[] decrypt(byte[] crypted, byte[] passphrase) throws Exception {
        return _decrypt(Base64.getDecoder().decode(crypted), passphrase);
        /**
         * This Method is used to Decode the Crypted text generated by the byte[]
         * encrypt method
         * in byte[] array into decrypted byte[] array
         */
    }

    public static void main(String[] args) throws Exception {
        /*
         * Create an object of PassGen class to generate a strong password to
         * pass it as input to String text.
         * 
         */
        Scanner sc = new Scanner(System.in);
        PassGen strongPassword = new PassGen(); // Object of PassGen Class
        KeyGen key = new KeyGen(); // Object of KeyGen Class
        System.out.println("Please enter the Lenght of the Password to be Encrypted.");
        System.out.println("Minimum length is '4'!!!");
        String text = strongPassword.generatePassword(sc.nextInt());
        // Password to be Generated has been Generated from PassGen Class
        System.out.println("Password Generated: " + text);
        // Key to be used to Encrypt and Decrypt Password has been Generated from KeyGen
        // Class
        String pass = key.generateKey();
        pass.trim();
        System.out.println("Key Generated: " + pass + "\n");
        byte[] text_bytes = text.getBytes(); // Converting the Password to Bytes Array
        byte[] pass_bytes = pass.getBytes(); // Converting the Key to Bytes Array

        // @Encryption
        String encrypted = Aes256.encrypt(text, pass);
        System.out.println("Encrypted Bits: " + encrypted);
        byte[] encrypted_bytes = Aes256.encrypt(text_bytes, pass_bytes); // Byte[] Array Encryption

        // @Decryption
        String decrypted = Aes256.decrypt(encrypted, pass);
        System.out.println("Decrypted Bits: " + decrypted);
        byte[] decrypted_bytes = Aes256.decrypt(encrypted_bytes, pass_bytes); // Byte[] Array Decryption
    }
}

class KeyGen {

    public String generateKey() {
        try {
            KeyGenerator keygen = KeyGenerator.getInstance("AES");
            keygen.init(256);
            byte[] key = keygen.generateKey().getEncoded();
            String strKey = String.valueOf(key);
            return strKey;
        } catch (Exception exception) {
            return "";
        }
    }

}

class PassGen {
    // Scanner sc = new Scanner(System.in);

    public static void main(String[] args) {
        Scanner sc = new Scanner(System.in);
        System.out.println("Please enter the length of the Key required: ");
        /*
         * Here the Length of the key to be generated is a minimum of 4
         * characters, and the length is to be taken from web page
         * (front end) using range bar or length input in the front end
         */
        // try {
        // new PassGen().client();
        // }catch(Exception exx) {}
        PassGen obj = new PassGen();
        int n = sc.nextInt();
        System.out.println(obj.generatePassword(n));

    }

    // void client()throws Exception
    // {
    // Socket s=new Socket("192.168.137.1",9999);
    // DataInputStream dis=new DataInputStream(s.getInputStream());
    // DataOutputStream dout=new DataOutputStream(s.getOutputStream());
    // String str=dis.readUTF();
    // System.out.println(str);
    // }
    String generatePassword(int length) {
        String capitalCaseLetters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        String lowerCaseLetters = "abcdefghijklmnopqrstuvwxyz";
        String specialCharacters = "!@#$%&";
        String numbers = "1234567890";
        String combinedChars = capitalCaseLetters + lowerCaseLetters + specialCharacters + numbers;
        Random random = new Random();
        char[] password = new char[length];

        password[0] = lowerCaseLetters.charAt(random.nextInt(lowerCaseLetters.length()));
        password[1] = capitalCaseLetters.charAt(random.nextInt(capitalCaseLetters.length()));
        password[2] = specialCharacters.charAt(random.nextInt(specialCharacters.length()));
        password[3] = numbers.charAt(random.nextInt(numbers.length()));

        for (int i = 4; i < length; i++) {
            password[i] = combinedChars.charAt(random.nextInt(combinedChars.length()));
        }
        String strPass = String.copyValueOf(password);
        return strPass;
    }

}

/**
 * This class is the internal functioning of the entire encryption and
 * decryption
 * process of the program. The Encryption and Decryption has been achieved by
 * methods @_encrypt and @__decrypt.
 * 
 * @_encyrpt->I/P(Password and Key)It is a Byte Array method which returns a
 *                         byte Array
 *                         thus in @Aes256 we have a method byte[] encrypt to
 *                         convert it into String.
 * @_decyrpt->I/P(Encrypted Text and Key)It is a Byte Array method which returns
 *                          a byte Array
 *                          thus in @Aes256 we have a method byte[] decrypt to
 *                          convert it into String.
 * @deriveKeyAndIv->This method is mainly included to make the generated Cipher
 *                       Text
 *                       resistant against many types of Brute Force Attacks.
 */
abstract class AbstractAes256 {
    // Generate the random salt
    protected static final byte[] SALTED = "Salted__".getBytes(US_ASCII);

    /**
     * The salt is random data very often used in cryptography
     * as additional input to a hash function.Doing encryption and decryption
     * of a String with a salt implies that you should: Read an initial String.
     * BASE64Encoder(A utility class to decode a Base64 encoded String to a
     * ByteArray) to decode the String to a byte array. The objective of salting
     * is to protect against brute force attacks against hashed passwords.
     */

    /**
     * Internal encrypt function
     * Input text to encrypt
     * The passphrase
     * Encrypted data
     * Throws Exceptions
     * 
     * @SecureRandom()->Constructs a secure random number generator (RNG)
     *                             to use for salting of the bits.
     * @generateSeed(int n)->Returns the given number of seed bytes,which is used
     *                   to seed other random number generators
     *                   @Cipher.init()->Init(CipherMode, IKey, AlgorithmParameters,
     *                   SecureRandom)
     *                   Initializes this cipher instance with the specified key,
     *                   algorithm parameters
     *                   and a source of randomness.
     * 
     */
    protected static byte[] _encrypt(byte[] input, byte[] passphrase) throws Exception {
        byte[] salt = (new SecureRandom()).generateSeed(8);
        Object[] keyIv = deriveKeyAndIv(passphrase, salt);

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec((byte[]) keyIv[0], "AES"),
                new IvParameterSpec((byte[]) keyIv[1]));
        // ENCRYPT_MODE->Constant used to initialize cipher to encryption mode.
        byte[] enc = cipher.doFinal(input);
        return concat(concat(SALTED, salt), enc);
    }

    /**
     * Internal decrypt function
     * 
     * @param data       Text in bytes to decrypt
     * @param passphrase The passphrase
     * @return Decrypted data in bytes
     * @throws Exception Throws exceptions
     */
    protected static byte[] _decrypt(byte[] data, byte[] passphrase) throws Exception {
        byte[] salt = Arrays.copyOfRange(data, 8, 16);

        if (!Arrays.equals(Arrays.copyOfRange(data, 0, 8), SALTED)) {
            throw new IllegalArgumentException("Invalid crypted data");
        }

        Object[] keyIv = deriveKeyAndIv(passphrase, salt);

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec((byte[]) keyIv[0], "AES"),
                new IvParameterSpec((byte[]) keyIv[1]));
        return cipher.doFinal(data, 16, data.length - 16);
    }

    /**
     * Derive key and iv
     * 
     * @param passphrase Passphrase
     * @param salt       Salt
     * @return Array of key and iv
     * @throws Exception Throws exceptions
     */
    protected static Object[] deriveKeyAndIv(byte[] passphrase, byte[] salt) throws Exception {
        final MessageDigest md5 = MessageDigest.getInstance("MD5");
        final byte[] passSalt = concat(passphrase, salt);
        byte[] dx = new byte[0];
        byte[] di = new byte[0];

        for (int i = 0; i < 3; i++) {
            di = md5.digest(concat(di, passSalt));
            dx = concat(dx, di);
        }

        return new Object[] { Arrays.copyOfRange(dx, 0, 32), Arrays.copyOfRange(dx, 32, 48) };
    }

    /**
     * Concatenate bytes
     * 
     * @param a First array
     * @param b Second array
     * @return Concatenated bytes
     */
    protected static byte[] concat(byte[] a, byte[] b) {
        byte[] c = new byte[a.length + b.length];
        System.arraycopy(a, 0, c, 0, a.length);
        System.arraycopy(b, 0, c, a.length, b.length);
        return c;
    }
}
