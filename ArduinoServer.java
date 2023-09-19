import java.io.*;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import com.google.crypto.tink.subtle.X25519;

public class ArduinoServer {
    public volatile static boolean intrusionDetected = false;

    // Secret keys for AES
    private static final byte[] secretKey = {
            (byte) 0x4a, (byte) 0x5d, (byte) 0x9d, (byte) 0x5b, (byte) 0xa4, (byte) 0xce, (byte) 0x2d, (byte) 0xe1,
            (byte) 0x72, (byte) 0x8e, (byte) 0x3b, (byte) 0xf4, (byte) 0x80, (byte) 0x35, (byte) 0x0f, (byte) 0x25
    };

    static byte[] monitor_public = {
            (byte) 0x85, (byte) 0x20, (byte) 0xf0, (byte) 0x09, (byte) 0x89, (byte) 0x30, (byte) 0xa7, (byte) 0x54,
            (byte) 0x74, (byte) 0x8b, (byte) 0x7d, (byte) 0xdc, (byte) 0xb4, (byte) 0x3e, (byte) 0xf7, (byte) 0x5a,
            (byte) 0x0d, (byte) 0xbf, (byte) 0x3a, (byte) 0x0d, (byte) 0x26, (byte) 0x38, (byte) 0x1a, (byte) 0xf4,
            (byte) 0xeb, (byte) 0xa4, (byte) 0xa9, (byte) 0x8e, (byte) 0xaa, (byte) 0x9b, (byte) 0x4e, (byte) 0x6a
    };

    static byte[] controller_public = {
            (byte) 0x85, (byte) 0x20, (byte) 0xf0, (byte) 0x09, (byte) 0x89, (byte) 0x30, (byte) 0xa7, (byte) 0x54,
            (byte) 0x74, (byte) 0x8b, (byte) 0x7d, (byte) 0xdc, (byte) 0xb4, (byte) 0x3e, (byte) 0xf7, (byte) 0x5a,
            (byte) 0x0d, (byte) 0xbf, (byte) 0x3a, (byte) 0x0d, (byte) 0x26, (byte) 0x38, (byte) 0x1a, (byte) 0xf4,
            (byte) 0xeb, (byte) 0xa4, (byte) 0xa9, (byte) 0x8e, (byte) 0xaa, (byte) 0x9b, (byte) 0x4e, (byte) 0x6a
    };

    static byte[] server_private = {
            (byte) 0x5d, (byte) 0xab, (byte) 0x08, (byte) 0x7e, (byte) 0x62, (byte) 0x4a, (byte) 0x8a, (byte) 0x4b,
            (byte) 0x79, (byte) 0xe1, (byte) 0x7f, (byte) 0x8b, (byte) 0x83, (byte) 0x80, (byte) 0x0e, (byte) 0xe6,
            (byte) 0x6f, (byte) 0x3b, (byte) 0xb1, (byte) 0x29, (byte) 0x26, (byte) 0x18, (byte) 0xb6, (byte) 0xfd,
            (byte) 0x1c, (byte) 0x2f, (byte) 0x8b, (byte) 0x27, (byte) 0xff, (byte) 0x88, (byte) 0xe0, (byte) 0xeb};

    static byte[] monitorIv = {
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x30, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x01
    };

    static byte[] controllerIv = {
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x40, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x01
    };

    static byte[] sharedSecretM;
    static byte[] sharedSecretC;

    public static void main(String[] args) throws UnknownHostException {
        int serverPort = 1234;

        // Compute the shared secret
        byte[] secretMonitor;
        byte[] secretController;
        try {
            secretMonitor = X25519.computeSharedSecret(server_private, monitor_public);
            secretController = X25519.computeSharedSecret(server_private, controller_public);
        } catch (InvalidKeyException e) {
            throw new RuntimeException(e);
        }
        sharedSecretM = new byte[16];
        sharedSecretC = new byte[16];
        for (int i = 0; i < 16; i++) {
            sharedSecretM[i] = secretMonitor[i];
            //System.out.print(sharedSecretM[i] & 0xFF);
            //System.out.print(" ");
        }
        //System.out.println(" ");
        for (int i = 0; i < 16; i++) {
            sharedSecretC[i] = secretController[i];
            //System.out.print(sharedSecretC[i] & 0xFF);
            //System.out.print(" ");
        }
        //System.out.println(" ");

        try {
            ServerSocket serverSocket = new ServerSocket(serverPort);
            System.out.println("SERVE UP, WAITING FOR CONNECTIONS...");

            while (true) {
                Socket clientSocket = serverSocket.accept();
                System.out.println("CLIENT CONNECTED: " + clientSocket.getInetAddress());

                Thread clientThread = new Thread(() -> handleClient(clientSocket));
                clientThread.start();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static void handleClient(Socket clientSocket) {

        try {
            OutputStream out = clientSocket.getOutputStream();
            BufferedReader in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
            String line = in.readLine();

            // Handle the Arduino Monitor
            if (line.equals("0")) {
                System.out.println("Monitor connected");

                //Generate the random string
                String uniqueString = generateRandomString(16);
                System.out.println("Unique String: " + uniqueString);

                // Crypt the random string using AES
                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                //secretKeySpec = new SecretKeySpec(sharedSecretM, "AES");
                Key secretKeySpec = new SecretKeySpec(secretKey, "AES");
                cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, new IvParameterSpec(monitorIv));
                byte[] ciphertext = cipher.doFinal(uniqueString.getBytes());
                out.write(ciphertext);

                // Update the IV vector
                for (int i = 0; i < 16; i++) monitorIv[i] ^= uniqueString.getBytes()[15] & 0xFF;

                while ((line = in.readLine()) != null) {
                    // Read and parse the message from the Monitor
                    System.out.println(line);
                    String[] byteStrings = line.split(" ");
                    byte[] encryptedBytes = new byte[byteStrings.length];

                    for (int i = 0; i < byteStrings.length; i++) {
                        encryptedBytes[i] = (byte) Integer.parseInt(byteStrings[i]);
                    }

                    //Decrypt the massage sent from Monitor
                    cipher = Cipher.getInstance("AES/CBC/NoPadding");
                    //secretKeySpec = new SecretKeySpec(sharedSecretM, "AES");
                    secretKeySpec = new SecretKeySpec(secretKey, "AES");
                    cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, new IvParameterSpec(monitorIv));
                    byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
                    System.out.println(String.valueOf(decryptedBytes[0]));

                    //Check if the message means a locker manumission
                    if (String.valueOf(decryptedBytes[0]).equals("104")) {
                        intrusionDetected = true;
                        System.out.println("Intrusion Detected");
                        //break;
                    }
                }
                // Handle the Arduino Controller
            } else if (line.equals("1")) {
                System.out.println("Controller connected");
                while (true) {
                    //Check if there was a manumission
                    if (intrusionDetected) {

                        // Crypt the code and send it to the Arduino Controller
                        System.out.println("in");
                        int code = 123456;
                        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

                        //Key secretKeySpec = new SecretKeySpec(sharedSecretC, "AES");
                        Key secretKeySpec = new SecretKeySpec(secretKey, "AES");
                        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, new IvParameterSpec(controllerIv));
                        byte[] ciphertext = cipher.doFinal(Integer.toString(code).getBytes());
                        System.out.println(Arrays.toString(ciphertext));

                        out.write(ciphertext);
                        intrusionDetected = false;
                        break;
                    }
                }
            }
            clientSocket.close();
            System.out.println("CLIENT DISCONNECTED: " + clientSocket.getInetAddress());
        } catch (IOException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException | NoSuchAlgorithmException | InvalidKeyException | IllegalBlockSizeException |
                 BadPaddingException | InvalidAlgorithmParameterException e) {
            throw new RuntimeException(e);
        }
    }

    public static String generateRandomString(int length) {
        String characters = "abcdefghijklmnopqrstuvwxyz";
        int charactersLength = characters.length();
        Random random = new Random();
        StringBuilder sb = new StringBuilder(length);

        for (int i = 0; i < length; i++) {
            int randomIndex = random.nextInt(charactersLength);
            char randomChar = characters.charAt(randomIndex);
            sb.append(randomChar);
        }

        return sb.toString();
    }
}
