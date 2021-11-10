import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.io.File;
import java.io.FileOutputStream;
import java.util.Arrays;

public class Assignment1 implements Assignment1Interface {

    // create our random generator
    private static SecureRandom secureRandomNumber = new SecureRandom();

    public static void main(String[] args) throws GeneralSecurityException, IOException {

        // create instance of our interface to use our functions
        Assignment1Interface inter = new Assignment1();

        // create our password string
        String pass = "Ax$Q=CBFy+&9<',K";

        // our source files to input our salt and IV hex values
        String IV_File = "src\\IV.txt";
        String Salt_file = "src\\Salt.txt";
        String Encryption_file = "src\\Encryption.txt";
        String Password_file = "src\\Password.txt";

        // get our IV using our random 16 bytes generator
        byte[] iv = random16bytes();
        // System.out.println("iv: " + Arrays.toString(iv));

        // write our IV to our file
        writeToFile(IV_File, ByteArrayHexString(iv));

        // get our random salt
        byte[] randSalt = random16bytes();

        // write our salt to our file
        writeToFile(Salt_file, ByteArrayHexString(randSalt));

        // Put our password into bytes to be used within our generateKey function
        byte[] passwordInBytes = pass.getBytes(StandardCharsets.UTF_8);

        // call our pre-specified interface method on our password and salt
        byte[] key = inter.generateKey(passwordInBytes, randSalt);

        // hash our key using SHA-256e
        byte[] hashedKey = hashKey(key);

        // read in our assignment class for encryption

        // This is local to my machine, must be changed to read in file correctly from
        // your own machine
        Path path = Paths.get("C:\\Assignment1\\Assignment1.class");

        // get our file in byte form
        byte[] fileInBytes = Files.readAllBytes(path);

        // specifying our ModExp variables
        BigInteger exponent = new BigInteger("65537", 10);
        BigInteger modulus = new BigInteger(
                "c406136c12640a665900a9df4df63a84fc855927b729a3a106fb3f379e8e4190ebba442f67b93402e535b18a5777e6490e67dbee954bb02175e43b6481e7563d3f9ff338f07950d1553ee6c343d3f8148f71b4d2df8da7efb39f846ac07c865201fbb35ea4d71dc5f858d9d41aaa856d50dc2d2732582f80e7d38c32aba87ba9",
                16);

        // Running our functions
        byte[] ciphertext = inter.encryptAES(fileInBytes, iv, hashedKey);

        byte[] plaintext = inter.decryptAES(ciphertext, iv, hashedKey);

        byte[] encryptPass = inter.encryptRSA(passwordInBytes, exponent, modulus);

        // write our encrypted AES input file to our Encryption text file
        writeToFile(Encryption_file, ByteArrayHexString(ciphertext));
        writeToFile(Password_file, ByteArrayHexString(encryptPass));

    }

    // Our hashing function using "SHA-256", it loops and hashes it 200 times
    public static byte[] hashKey(byte[] simplekey) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hashKey = simplekey;
        for (int i = 1; i <= 200; i++) {
            hashKey = digest.digest(hashKey);
        }
        return hashKey;
    }

    // our random 16 bytes generator - 16 bytes == 128 bits
    public static byte[] random16bytes() {
        byte[] arr = new byte[16];

        // Place the generated random bytes into an array
        secureRandomNumber.nextBytes(arr);

        return arr;
    }

    // simple function to change an array to a hex String, helpful for writing to
    // file
    // adapted from
    // "https://stackoverflow.com/questions/9655181/how-to-convert-a-byte-array-to-a-hex-string-in-java"

    public static String ByteArrayHexString(byte[] bytes) {
        StringBuilder str = new StringBuilder();
        for (byte b : bytes) {
            str.append(String.format("%02x", b));
        }

        return str.toString();
    }

    // our function to write to file
    public static void writeToFile(String FileName, String fileData) throws IOException {

        File outputFile = new File(FileName);
        FileOutputStream stream = new FileOutputStream(outputFile);

        // We then encode our file data using "UTF-8"

        stream.write(fileData.getBytes(StandardCharsets.UTF_8));
        stream.close();
    }

    // Generate Key Function that concatenates our salt and password together to get
    // our key
    @Override
    public byte[] generateKey(byte[] password, byte[] salt) {

        // concatenate our password and salt p||s
        byte[] key = new byte[password.length + salt.length];
        System.arraycopy(password, 0, key, 0, password.length);
        System.arraycopy(salt, 0, key, password.length, salt.length);

        return key;
    }

    // Created with help from
    // https://howtodoinjava.com/java/java-security/aes-256-encryption-decryption/
    @Override
    public byte[] encryptAES(byte[] plaintext, byte[] iv, byte[] key) {

        try {
            // creating our IV
            IvParameterSpec IV = new IvParameterSpec(iv);
            // storing our key as an AES key, avoiding the secret key factory
            SecretKeySpec secret_key = new SecretKeySpec(key, "AES");

            /// Creating our padding method
            int plain_text_length = plaintext.length;

            // finding how much padding is needed by finding the remainder left from the
            // length
            int padding = 16 - (plain_text_length % 16);

            // Create our byte array for our length and padding
            byte[] padded_plain_text = new byte[plain_text_length + padding];

            System.arraycopy(plaintext, 0, padded_plain_text, 0, plaintext.length);

            // Our loop to add padding, add a 1 to start and then for the length of our
            // file, add zeros

            padded_plain_text[plain_text_length] = (byte) 1;
            for (int i = plain_text_length + 1; i < padding; i++) {
                padded_plain_text[i] = (byte) 0;

            }

            // Encrypt our file with our key and IV
            Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, secret_key, IV);

            // Perform the encryption
            byte[] encrypted_plain_text = cipher.doFinal(padded_plain_text);
            // System.out.println(Arrays.toString(padded_plain_text));
            return encrypted_plain_text;

        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return null;
    }

    @Override
    public byte[] decryptAES(byte[] ciphertext, byte[] iv, byte[] key) {

        try {
            // Decrypting our ciphertext

            IvParameterSpec IV = new IvParameterSpec(iv);
            SecretKeySpec secret_key = new SecretKeySpec(key, "AES");
            Cipher decrypt = Cipher.getInstance("AES/CBC/NoPadding");
            decrypt.init(Cipher.DECRYPT_MODE, secret_key, IV);
            byte[] plainTextBytes = decrypt.doFinal(ciphertext);

            // Remove our trailing padding that could be 1 or 0
            int i = plainTextBytes.length - 1;
            while (i >= 0 && plainTextBytes[i] == 0 || plainTextBytes[i] == 1) {
                --i;
            }

            byte[] decodedText = Arrays.copyOf(plainTextBytes, i + 1);
            // System.out.println(Arrays.toString(decodedText));
            return decodedText;

        }

        catch (Exception ex) {
            ex.printStackTrace();
        }
        return null;
    }

    @Override
    public byte[] encryptRSA(byte[] plaintext, BigInteger exponent, BigInteger modulus) {

        try {

            // Encrypting using our modExp function

            BigInteger passwordToEncrypt = new BigInteger(plaintext);
            byte[] encryptedPassword = modExp(passwordToEncrypt, exponent, modulus).toByteArray();
            return encryptedPassword;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    @Override
    public BigInteger modExp(BigInteger base, BigInteger exponent, BigInteger modulus) {
        // the Right to Left approach to modular exponentiation

        // find the length of our exponent
        int exp = exponent.bitLength();

        // set our y to one to start
        BigInteger y = BigInteger.ONE;

        for (int i = 0; i < exp; i++) {
            // if the bit is set as 1 or 0
            if (exponent.testBit(i)) {
                // first part of algo - y = y * base (mod n)
                y = y.multiply(base).mod(modulus);
            }
            // base = base^2 (mod n)
            base = (base.multiply(base)).mod(modulus);
        }
        return y;

    }

}
