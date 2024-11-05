import java.io.*;
import java.math.BigInteger;
import java.net.Socket;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
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

            // Proceso de comunicación seguro con el servidor
            iniciarComunicacion(out, in);

            // Enviar consulta al servidor
            startTime = System.nanoTime();
            Random rand = new Random();
            int consulta = rand.nextInt(32); // Genera una consulta aleatoria
            byte[] consulta_encriptada = cifrarMensaje(String.valueOf(consulta).getBytes());
            endTime = System.nanoTime();
            out.writeObject(consulta_encriptada);
            this.tiempoCifrarConsulta = endTime - startTime;

            // Generar código de autenticación para la consulta
            startTime = System.nanoTime();
            byte[] firmaHmac = generarCodigoAutenticacion(String.valueOf(consulta).getBytes());
            endTime = System.nanoTime();
            this.tiempoGenerarCodigoAutenticacion = endTime - startTime;
            out.writeObject(firmaHmac);

            // Recibir respuesta del servidor y verificarla
            byte[] rta_enc = (byte[]) in.readObject();
            byte[] rta_dec = descifrarMensaje(rta_enc);
            byte[] rta_hmac = (byte[]) in.readObject();
            byte[] rta_revisar = generarCodigoAutenticacion(rta_dec);

            if (Arrays.equals(rta_revisar, rta_hmac)) {
                String estadoRecibido = new String(rta_dec).trim();
                System.out.println("Estado del paquete: " + estadoRecibido);
                out.writeObject("OK");
            } else {
                System.out.println("Error en la consulta");
                out.writeObject("ERROR");
            }
            this.barrier.await();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void iniciarComunicacion(ObjectOutputStream out, ObjectInputStream in) throws Exception {
        // Paso 1: Generar un reto aleatorio y enviarlo al servidor
        SecureRandom random = new SecureRandom();
        byte[] reto = new byte[16];
        random.nextBytes(reto);
        out.writeObject("SECURE INIT");
        out.writeObject(reto);

        // Paso 4: Recibir reto cifrado del servidor y verificar la firma
        byte[] encryptedReto = (byte[]) in.readObject();
        File file = new File("server_key.txt");

        // Leer llave pública del servidor desde archivo
        try (Scanner scanner = new Scanner(file)) {
            String llaveCadena = scanner.nextLine();
            servidorPublicKey = KeyFactory.getInstance("RSA")
                    .generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(llaveCadena)));
        }

        // Verificar firma del reto
        Signature firma = Signature.getInstance("SHA256withRSA");
        firma.initVerify(servidorPublicKey);
        firma.update(reto);
        boolean valido = firma.verify(encryptedReto);
        if (valido) {
            out.writeObject("OK");
        } else {
            out.writeObject("ERROR");
            throw new SecurityException("Firma de reto inválida");
        }

        // Paso 8: Recibir valores de Diffie-Hellman (g, p, gx) e iv
        g = (BigInteger) in.readObject();
        p = (BigInteger) in.readObject();
        gx = (BigInteger) in.readObject();
        iv = (byte[]) in.readObject();

        // Verificar integridad de los parámetros de Diffie-Hellman usando firma
        String g_c = g.toString();
        String p_c = p.toString();
        String gx_c = gx.toString();
        String msgConcat = g_c + p_c + gx_c;
        byte[] encryptedMsg = (byte[]) in.readObject();

        firma.initVerify(servidorPublicKey);
        firma.update(msgConcat.getBytes());
        valido = firma.verify(encryptedMsg);

        if (!valido) {
            out.writeObject("ERROR");
            throw new SecurityException("Firma de parámetros Diffie-Hellman inválida");
        } else {
            out.writeObject("OK");
        }

        // Paso 9: Generar parte del cliente en Diffie-Hellman
        y = gx.mod(p);
        gy = g.modPow(y, p);
        out.writeObject(gy);

        // Paso 11a: Generar clave secreta compartida
        gxy = gx.modPow(y, p);
        BigInteger secretKey = gxy.mod(p);

        // Derivar llaves simétricas a partir de SHA-512 del secreto compartido
        MessageDigest sha512 = MessageDigest.getInstance("SHA-512");
        byte[] hash = sha512.digest(secretKey.toString().getBytes());

        k_ab1 = Arrays.copyOfRange(hash, 0, hash.length / 2); // Llave para cifrado
        k_ab2 = Arrays.copyOfRange(hash, hash.length / 2, hash.length); // Llave para autenticación
        llave_simetrica = new SecretKeySpec(k_ab1, "AES");
        llave_autenticacion = new SecretKeySpec(k_ab2, "HmacSHA256");
    }

    private byte[] cifrarMensaje(byte[] mensaje) {
        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, llave_simetrica, new IvParameterSpec(iv));
            return cipher.doFinal(mensaje);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    private byte[] descifrarMensaje(byte[] mensajeCifrado) {
        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, llave_simetrica, new IvParameterSpec(iv));
            return cipher.doFinal(mensajeCifrado);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    private byte[] generarCodigoAutenticacion(byte[] mensaje) {
        try {
            Mac hmacSha256 = Mac.getInstance("HmacSHA256");
            hmacSha256.init(llave_autenticacion);
            return hmacSha256.doFinal(mensaje);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }
}
