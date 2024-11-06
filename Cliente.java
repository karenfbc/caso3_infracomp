import java.io.*;
import java.math.BigInteger;
import java.net.Socket;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Random;
import java.util.Scanner;
import java.util.concurrent.CyclicBarrier;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Cliente extends Thread {
    private Integer Numerito;
    private BigInteger g, p, gx, y, gy, gxy;
    private byte[] k_ab1, k_ab2;
    private SecretKey llave_simetrica, llave_autenticacion;
    public static final int PORT = 1234;
    public static final String SERVER = "localhost";
    private PublicKey servidorPublicKey;
    private byte[] iv;
    private String login = "login";
    private String contrasenia = "1234";
    private long tiempoVerificarFirma, tiempoGenerarGY, tiempoCifrarConsulta, tiempoGenerarCodigoAutenticacion;
    private CyclicBarrier barrier;

    public Cliente(Integer numerito, CyclicBarrier barrier) {
        Numerito = numerito;
        this.barrier = barrier;
    }

    public long getTiempoVerificarFirma() {
        return tiempoVerificarFirma;
    }

    public long getTiempoGenerarGY() {
        return tiempoGenerarGY;
    }

    public long getTiempoCifrarConsulta() {
        return tiempoCifrarConsulta;
    }

    public long getTiempoGenerarCodigoAutenticacion() {
        return tiempoGenerarCodigoAutenticacion;
    }

    public Integer getNumerito() {
        return Numerito;
    }

    // Convertir de cadena hexadecimal a bytes
    private byte[] hexToString(String cadena) {
        int len = cadena.length();
        byte[] bytes = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            bytes[i / 2] = (byte) ((Character.digit(cadena.charAt(i), 16) << 4)
                    + Character.digit(cadena.charAt(i + 1), 16));
        }

        return bytes;
    }

    @Override
    public void run() {


        try (Socket socket = new Socket(SERVER, PORT);
                ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
                ObjectInputStream in = new ObjectInputStream(socket.getInputStream())) {

            long startTime, endTime;

            // Paso 1
            SecureRandom random = new SecureRandom();
            byte[] reto = new byte[16];
            random.nextBytes(reto);
            out.writeObject("SECURE INIT");
            out.writeObject(reto);
            System.out.println("Paso 1: Cliente OK");

            // Cargar la clave pública
            File file = new File("server_public_key.txt");
            try {
                Scanner scanner = new Scanner(file);
                String llaveCadena = scanner.nextLine();
                servidorPublicKey = KeyFactory.getInstance("RSA")
                        .generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(llaveCadena)));
                scanner.close();
                System.out.println("Clave pública cargada correctamente: " + servidorPublicKey);
            } catch (Exception e) {
                e.printStackTrace();
            }

            // Paso 2: Cifrar el reto usando la clave pública del servidor
            Cipher cipher1 = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher1.init(Cipher.ENCRYPT_MODE, servidorPublicKey);
            byte[] R = cipher1.doFinal(reto); // Cifra el reto
            out.writeObject(R); // Enviar el reto cifrado al servidor
            System.out.println("Paso 2: Cliente OK");

            // Paso 4
            byte[] Rta = (byte[]) in.readObject();
            startTime = System.nanoTime();
            Signature firma = Signature.getInstance("SHA256withRSA");
            firma.initVerify(servidorPublicKey);
            firma.update(reto);
            boolean valido = firma.verify(R);
            endTime = System.nanoTime();
            this.tiempoVerificarFirma = endTime - startTime;
            System.out.println("Paso 4: Cliente OK");

            // Paso 5

            if (valido) {
                out.writeObject("OK");
            } else {
                out.writeObject("ERROR");
                return;
            }

            System.out.println("Paso 5: Cliente OK");

            // Paso 8
            g = (BigInteger) in.readObject();
            p = (BigInteger) in.readObject();
            gx = (BigInteger) in.readObject();
            iv = (byte[]) in.readObject();

            String g_c = g.toString();
            String p_c = p.toString();
            String gx_c = gx.toString();
            String msgConcat = String.join(g_c, p_c, gx_c);

            byte[] encryptedMsg = (byte[]) in.readObject();

            firma.initVerify(servidorPublicKey);
            firma.update(msgConcat.getBytes());
            valido = firma.verify(encryptedMsg);

            System.out.println("Paso 8: Cliente OK");

            // Paso 9

            if (valido) {
                out.writeObject("OK");
            } else {
                out.writeObject("ERROR");
                return;
            }
            startTime = System.nanoTime();
            y = gx.mod(p);
            gy = g.modPow(y, BigInteger.TEN);
            endTime = System.nanoTime();
            this.tiempoGenerarGY = endTime - startTime;

            System.out.println("Paso 9: Cliente OK");

            // Paso 10
            out.writeObject(gy);

            System.out.println("Paso 10: Cliente OK");

            // Paso 11a
            gxy = gx.modPow(y, BigInteger.TEN);
            BigInteger secretKey = gxy.mod(p);

            MessageDigest sha512 = MessageDigest.getInstance("SHA-512");
            byte[] hash = sha512.digest(secretKey.toString().getBytes());

            k_ab1 = Arrays.copyOfRange(hash, 0, (hash.length / 2));
            k_ab2 = Arrays.copyOfRange(hash, (hash.length / 2), hash.length);

            llave_simetrica = new SecretKeySpec(k_ab1, "AES");

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, llave_simetrica, new IvParameterSpec(iv));

            System.out.println("Paso 11: Cliente OK");

            // Preparacion 13
            byte[] login_encriptado = cipher.doFinal(login.getBytes());
            MessageDigest sha512Login = MessageDigest.getInstance("SHA-512");
            byte[] loginHash = sha512Login.digest(login.getBytes());
            byte[] loginHashCifrado = cipher.doFinal(loginHash);
            ArrayList<byte[]> loginYHash = new ArrayList<>();
            loginYHash.add(login_encriptado);
            loginYHash.add(loginHashCifrado);

            // Paso 13. Envio de Login cifrado con su Hash
            out.writeObject(loginYHash);

            System.out.println("Paso 13: Cliente OK");

            // Preparacion 14
            byte[] contra_encriptada = cipher.doFinal(contrasenia.getBytes());
            MessageDigest sha512Contra = MessageDigest.getInstance("SHA-512");
            byte[] contraHash = sha512Contra.digest(contrasenia.getBytes());
            byte[] contraHashCifrado = cipher.doFinal(contraHash);
            ArrayList<byte[]> contraYHash = new ArrayList<>();
            contraYHash.add(contra_encriptada);
            contraYHash.add(contraHashCifrado);

            // Paso 14. Envio de Pasword cifrado con su Hash
            out.writeObject(contraYHash);

            System.out.println("Paso 14: Cliente OK");

            // Lecturas paso 12 y 16
            String continuar = (String) in.readObject();

            String ok = (String) in.readObject();

            System.out.println("Paso 12 y 16: Cliente OK");

            // Paso 17
            startTime = System.nanoTime();
            Random rand = new Random();
            int consulta = rand.nextInt(10);
            byte[] consulta_encriptada = cipher.doFinal(String.valueOf(consulta).getBytes());
            endTime = System.nanoTime();
            out.writeObject(consulta_encriptada);
            this.tiempoCifrarConsulta = endTime - startTime;

            System.out.println("Paso 17: Cliente OK");

            // Paso 18
            startTime = System.nanoTime();
            Mac hmacSha256 = Mac.getInstance("HmacSHA256");
            llave_autenticacion = new SecretKeySpec(k_ab2, "HmacSHA256");
            hmacSha256.init(llave_autenticacion);
            byte[] firmaHmac = hmacSha256.doFinal(String.valueOf(consulta).getBytes());
            endTime = System.nanoTime();
            this.tiempoGenerarCodigoAutenticacion= endTime - startTime;
            out.writeObject(firmaHmac);

            System.out.println("Paso 18: Cliente OK");

            // Paso 21
            cipher.init(Cipher.DECRYPT_MODE, llave_simetrica, new IvParameterSpec(iv));

            byte[] rta_enc = (byte[]) in.readObject();
            byte[] rta_dec = cipher.doFinal(rta_enc);
            byte[] rta_hmac = (byte[]) in.readObject();
            byte[] rta_revisar = hmacSha256.doFinal(rta_dec);

            System.out.println("Paso211: Cliente OK");
            // Paso
            if (new String(rta_revisar).equals(new String(rta_hmac))) {
                out.writeObject("OK");
                // System.out.println("Cliente con Id = " + this.getNumerito()+" completó el
                // proceso correctamente");
            } else {
                out.writeObject("ERROR");
                // System.out.println("Cliente con Id = " + this.getNumerito()+" NO PUDO
                // completar el proceso correctamente");
                return;
            }
            this.barrier.await();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}
