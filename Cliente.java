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

    // Estados de los paquetes
    public static final int EN_OFICINA = 0;
    public static final int RECOGIDO = 1;
    public static final int EN_CLASIFICACION = 2;
    public static final int DESPACHADO = 3;
    public static final int EN_ENTREGA = 4;
    public static final int ENTREGADO = 5;
    public static final int DESCONOCIDO = 6;

    private Integer Num;
    private BigInteger g, p, gx, y, gy, gxy;
    private byte[] k_ab1, k_ab2;
    private SecretKey llave_simetrica, llave_autenticacion;
    public static final int PORT = 1234;
    public static final String SERVER = "localhost";
    private PublicKey servidorPublicKey;
    private byte[] iv;
    private String uid = "uid";
    private String paqueteId = "12";
    private long tiempoVerificarFirma, tiempoGenerarGY, tiempoCifrarConsulta, tiempoGenerarCodigoAutenticacion;
    private CyclicBarrier barrier;

    public Cliente(Integer num, CyclicBarrier barrier) {
        Num = num;
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

    public Integer getNum() {
        return Num;
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

    public void ejecutar32Consultas() {
        for (int i = 0; i < 32; i++) {
            run(); 
        }
    }

    @Override
    public void run() {


        try (Socket socket = new Socket(SERVER, PORT);
                ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
                ObjectInputStream in = new ObjectInputStream(socket.getInputStream())) {

            long startTime, endTime;

            // Paso 1
        
            out.writeObject("SECINIT");    

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

            SecureRandom random = new SecureRandom();
            byte[] reto = new byte[16];
            random.nextBytes(reto);

            Cipher cipher1 = Cipher.getInstance("RSA");
            cipher1.init(Cipher.ENCRYPT_MODE, servidorPublicKey);
            byte[] R = cipher1.doFinal(reto); // Cifra el reto
            out.writeObject(R); // Enviar el reto cifrado al servidor
            System.out.println("Paso 2: Cliente OK");

            // Paso 4
            byte[] Rta = (byte[]) in.readObject();

            System.out.println("Paso 4: Cliente OK");

            // Paso 5 y 6

            if (Arrays.equals(Rta, reto)) {
                out.writeObject("OK");
            } else {
                out.writeObject("ERROR");
                return;
            }

            System.out.println("Paso 6: Cliente OK");

            // Paso 8

            g = (BigInteger) in.readObject();
            p = (BigInteger) in.readObject();
            gx = (BigInteger) in.readObject();

            String msgConcat = g.toString() + p.toString() + gx.toString();

            byte[] msgEncrypt = (byte[]) in.readObject();

            startTime = System.nanoTime();
            Signature signature = Signature.getInstance("SHA1withRSA");
            signature.initVerify(servidorPublicKey);

            signature.update(g.toByteArray());
            signature.update(p.toByteArray());
            signature.update(gx.toByteArray());

            boolean isVerified = signature.verify(msgEncrypt);

            endTime = System.nanoTime();
            this.tiempoVerificarFirma = endTime - startTime;

            if (isVerified) {
                out.writeObject("OK");
            } else {
                out.writeObject("ERROR");
                return;
            }

            System.out.println("Paso 8: Cliente OK");

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

            iv = (byte[]) in.readObject();

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, llave_simetrica, new IvParameterSpec(iv));

            System.out.println("Paso 11: Cliente OK");

            //paso 12

            System.out.println("Paso 12: Cliente OK");

            byte[] uid_encriptado = cipher.doFinal(uid.getBytes());
            MessageDigest sha512uid = MessageDigest.getInstance("SHA-512");
            byte[] uidHash = sha512uid.digest(uid.getBytes());
            byte[] uidHashCifrado = cipher.doFinal(uidHash);
            ArrayList<byte[]> UIDYHash = new ArrayList<>();
            UIDYHash.add(uid_encriptado);
            UIDYHash.add(uidHashCifrado);

            // Paso 13. Envio de uid cifrado con su Hash
            out.writeObject(UIDYHash);

            System.out.println("Paso 13: Cliente OK");

            byte[] paqueteId_encriptada = cipher.doFinal(paqueteId.getBytes());
            MessageDigest sha512paqueteId = MessageDigest.getInstance("SHA-512");
            byte[] paqueteIdHash = sha512paqueteId.digest(paqueteId.getBytes());
            byte[] paqueteIdHashCifrado = cipher.doFinal(paqueteIdHash);
            ArrayList<byte[]> paqueteIdYHash = new ArrayList<>();
            paqueteIdYHash.add(paqueteId_encriptada);
            paqueteIdYHash.add(paqueteIdHashCifrado);

            // Paso 14. Envio de paquete cifrado con su Hash
            out.writeObject(paqueteIdYHash);

            System.out.println("Paso 14: Cliente OK");

            // Paso 14

            startTime = System.nanoTime();
            Random rand = new Random();
            int consulta = rand.nextInt(10);
            byte[] consulta_encriptada = cipher.doFinal(String.valueOf(consulta).getBytes());
            endTime = System.nanoTime();
            out.writeObject(consulta_encriptada);
            this.tiempoCifrarConsulta = endTime - startTime;

            startTime = System.nanoTime();
            Mac hmacSha256 = Mac.getInstance("HmacSHA256");
            llave_autenticacion = new SecretKeySpec(k_ab2, "HmacSHA256");
            hmacSha256.init(llave_autenticacion);
            byte[] firmaHmac = hmacSha256.doFinal(String.valueOf(consulta).getBytes());
            endTime = System.nanoTime();
            this.tiempoGenerarCodigoAutenticacion= endTime - startTime;
            out.writeObject(firmaHmac);

            System.out.println("Paso 14: Cliente OK");

            // Paso 16
            cipher.init(Cipher.DECRYPT_MODE, llave_simetrica, new IvParameterSpec(iv));

            byte[] rta_enc = (byte[]) in.readObject();
            byte[] rta_dec = cipher.doFinal(rta_enc);
            byte[] rta_hmac = (byte[]) in.readObject();
            byte[] rta_revisar = hmacSha256.doFinal(rta_dec);

            System.out.println("Paso16: Cliente OK");

            // Paso 18
            if (new String(rta_revisar).equals(new String(rta_hmac))) {
                out.writeObject("TERMINAR");

            } else {
                out.writeObject("ERROR");
                return;
            }
            this.barrier.await();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}
