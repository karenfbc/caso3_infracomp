import java.io.*;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Random;
import java.util.Scanner;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Servidor extends Thread {

    private PrivateKey privada_servidor;
    private PublicKey publica_servidor;

    private String uid;
    private String paquete_id;

    private BigInteger p, x, y, g, gx, gy, gyx;
    private byte[] k_ab1, k_ab2;

    private SecretKey llave_simetrica, llave_autenticacion;
    private final int PORT = 1234;

    private Long TimeGenerarConsulta = 0L, TimeDescrifarConsulta = 0L, TimeVerificarCodigoAutenticacion = 0L;

    private byte[] hexToString(String cadena) {
        int len = cadena.length();
        byte[] bytes = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            bytes[i / 2] = (byte) ((Character.digit(cadena.charAt(i), 16) << 4)
                    + Character.digit(cadena.charAt(i + 1), 16));
        }

        return bytes;
    }

    public void setTimeGenerarConsulta(Long timeGenerarConsulta) {
        TimeGenerarConsulta = timeGenerarConsulta;
    }

    public void setTimeDescrifarConsulta(Long timeDescrifarConsulta) {
        TimeDescrifarConsulta = timeDescrifarConsulta;
    }

    public void setTimeVerificarCodigoAutenticacion(Long timeVerificarCodigoAutenticacion) {
        TimeVerificarCodigoAutenticacion = timeVerificarCodigoAutenticacion;
    }

    public Long getTimeGenerarConsulta() {
        return TimeGenerarConsulta;
    }

    public Long getTimeDescrifarConsulta() {
        return TimeDescrifarConsulta;
    }

    public Long getTimeVerificarCodigoAutenticacion() {
        return TimeVerificarCodigoAutenticacion;
    }

    private void generarLlave() {
        File file = new File("DiffieHellman.txt");

        try {
            Scanner scanner = new Scanner(file);

            // Cadena de bytes de p
            String dataP = (scanner.nextLine().split(","))[1];
            int gInt = Integer.parseInt((scanner.nextLine().split(","))[1]);
            g = BigInteger.valueOf(gInt);
            String pCadena = dataP.replace(":", "");

            // Decodificar p a big integer
            p = new BigInteger(hexToString(pCadena));
            // System.out.println(p);

            // Generar x
            Random random = new Random();

            x = new BigInteger(p.subtract(BigInteger.ONE).bitLength(), random);

            // Generar y
            gx = g.modPow(x, BigInteger.TEN);
            y = gx.mod(p);

            scanner.close();

        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }

    }

    @Override
    public void run() {

        generateKeys();

        System.out.println("Servidor comienza y espera en el puerto " + PORT);
        try (ServerSocket serverSocket = new ServerSocket(PORT, 1000000000)) {
            while (true) {
                try (Socket clientSocket = serverSocket.accept();
                        ObjectOutputStream out = new ObjectOutputStream(clientSocket.getOutputStream());
                        ObjectInputStream in = new ObjectInputStream(clientSocket.getInputStream())) {
                    Long startTime, endTime;


                    String initMessage = (String) in.readObject();
                    
                    // Paso 2: Recibir R

                    byte[] R = (byte[]) in.readObject();

                    System.out.println("Paso 2: Servidor OK");

                    // Paso 3: Calcular Rta= D(K_w-, R)
                    startTime = System.nanoTime();

                    Cipher cipher1 = Cipher.getInstance("RSA");
                    cipher1.init(Cipher.DECRYPT_MODE, privada_servidor);
                    byte[] Rta = cipher1.doFinal(R);
                    endTime = System.nanoTime();
                    this.TimeGenerarConsulta += endTime - startTime; 

                    System.out.println("Paso 3: Servidor OK");

                    // Paso 4: enviar Rta
                    out.writeObject(Rta);

                    System.out.println("Paso 4: Servidor OK");

                    // Paso 6: recibir "OK" o "ERROR"

                    String Mensaje = (String) in.readObject();

                    System.out.println("Paso 6: Servidor OK");

                    // Paso 7: Generar G, P, G^x
                    generarLlave();
                    System.out.println("Paso 7: Servidor OK");

                    // Paso 8: Enviar G, P, G^x, F(K_w-,(G,P,G^X))
                    out.writeObject(g);
                    out.writeObject(p);
                    out.writeObject(gx);

                    Signature firma = Signature.getInstance("SHA256withRSA");
                    String msgConcat = String.join(g.toString(), p.toString(), gx.toString());
                    firma.initSign(privada_servidor);
                    firma.update(msgConcat.getBytes()); // pasamos datos a firmar
                    byte[] msgEncrypt = firma.sign();
                    out.writeObject(msgEncrypt);

                    System.out.println("Paso 8: Servidor OK");

                    // Paso 10: recibir "OK" o "ERROR"

                    Mensaje = (String) in.readObject();

                    System.out.println("Paso 10: Servidor OK");

                    // Paso 11: recibir G^y
                    gy = (BigInteger) in.readObject();

                    System.out.println("Paso 11a: Servidor OK");

                    // Paso 11.b: Calcular (G^y)^x
                    gyx = gy.modPow(x, BigInteger.TEN);

                    BigInteger secretKey = gyx.mod(p);

                    MessageDigest sha512 = MessageDigest.getInstance("SHA-512");
                    byte[] hash = sha512.digest(secretKey.toString().getBytes());

                    k_ab1 = Arrays.copyOfRange(hash, 0, (hash.length / 2));
                    k_ab2 = Arrays.copyOfRange(hash, (hash.length / 2), hash.length);

                    System.out.println("Paso 11b: Servidor OK");

                    // Paso 12: enviar iv 
                    SecureRandom random = new SecureRandom();
                    byte[] iv = new byte[16];
                    random.nextBytes(iv);
                    out.writeObject(iv);

                    System.out.println("Paso 12: Servidor OK");

                    // Paso 15
                    llave_simetrica = new SecretKeySpec(k_ab1, "AES");

                    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                    cipher.init(Cipher.DECRYPT_MODE, llave_simetrica, new IvParameterSpec(iv));

                    System.out.println("Paso 15: Servidor OK");

                    // Paso 13: C(K_AB1, uid)

                    @SuppressWarnings("unchecked")
                    ArrayList<byte[]> UIDYHash = (ArrayList<byte[]>) in.readObject();
                    byte[] uid_dec = cipher.doFinal(UIDYHash.get(0));
                    byte[] hash_uid_dec = cipher.doFinal(UIDYHash.get(1));

                    System.out.println("Paso 13: Servidor OK");

                    // Paso 13: HMAC(K_AB2, uid)

                    Mac hmacSha256 = Mac.getInstance("HmacSHA256");
                    llave_autenticacion = new SecretKeySpec(k_ab2, "HmacSHA256");
                    hmacSha256.init(llave_autenticacion);

                    uid = new String(uid_dec);

                    byte[] hmac_revisar1 = hmacSha256.doFinal(hash_uid_dec);

                    System.out.println("Paso 13: Servidor OK");

                    // Paso 14: C(K_AB1, paquete_id)

                    cipher.init(Cipher.ENCRYPT_MODE, llave_simetrica, new IvParameterSpec(iv));
                    byte[] paqueteIdCiphertext = cipher.doFinal(paquete_id.getBytes());
                    out.writeObject(paqueteIdCiphertext);

                    System.out.println("Paso 14: Servidor OK");

                    // Paso 14: HMAC(K_AB2, paquete_id)

                    @SuppressWarnings("unchecked")
                    ArrayList<byte[]> paqueteIdYHash = (ArrayList<byte[]>) in.readObject();
                    byte[] contra_dec = cipher.doFinal(paqueteIdYHash.get(0));
                    byte[] hashContra_dec = cipher.doFinal(paqueteIdYHash.get(1));

                    paquete_id = new String(contra_dec);

                    byte[] hmac_revisar2 = hmacSha256.doFinal(hashContra_dec);

                    System.out.println("Paso 14: Servidor OK");

                    // Paso 15: Verificar y responder
                    if (Arrays.equals(hmac_revisar1, hmacSha256.doFinal(uid_dec)) && Arrays.equals(hmac_revisar2, hmacSha256.doFinal(paquete_id.getBytes()))) {
                        String estado = "OK";
                        out.writeObject(cipher.doFinal(estado.getBytes()));

                    byte[] estadoHmac = hmacSha256.doFinal(estado.getBytes());
                        out.writeObject(estadoHmac);
                    } else {
                        // Enviar error de autenticación si no coincide
                        String estado = "ERROR";
                        out.writeObject(cipher.doFinal(estado.getBytes()));

                        byte[] estadoHmac = hmacSha256.doFinal(estado.getBytes());
                        out.writeObject(estadoHmac);
                    }

                    System.out.println("Paso 15: Servidor OK");

                    // Paso 18: recibir "Terminar"
                        String terminar = (String) in.readObject();

                        System.out.println("Paso 18: Servidor OK");

                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void generateKeys() {
        try {
            // Crea el generador de par de llaves
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(512);

            // Genera el par de llaves
            KeyPair pair = keyGen.generateKeyPair();
            privada_servidor = pair.getPrivate();
            publica_servidor = pair.getPublic();

            String filename = "server_public_key.txt";
            byte[] publicKeyBytes = publica_servidor.getEncoded();
            String publicKeyString = Base64.getEncoder().encodeToString(publicKeyBytes);

            try {
                FileWriter fileWriter = new FileWriter(filename);
                BufferedWriter bufferedWriter = new BufferedWriter(fileWriter);
                bufferedWriter.write(publicKeyString);
                bufferedWriter.close();
            } catch (IOException e) {
                System.out.println("Ocurrió un error al escribir en el archivo: " + e.getMessage());
            }

        } catch (NoSuchAlgorithmException e) {
            System.err.println("Exception encountered " + e);
            e.printStackTrace();
        }
    }

}