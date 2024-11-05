import java.io.*;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;
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

    public static final int ENOFICINA = 0;
    public static final int RECOGIDO = 1;
    public static final int ENCLASIFICACION = 2;
    public static final int DESPACHADO = 3;
    public static final int ENENTREGA = 4;
    public static final int ENTREGADO = 5;
    public static final int DESCONOCIDO = 6;

    private static final Map<String, Map<String, Integer>> tablaPaquetes = new HashMap<>();

    static {
        for (int i = 0; i < 32; i++) {
            String userId = "user" + i;
            String paqueteId = "package" + i;
            int estado = i % 6;
            tablaPaquetes.computeIfAbsent(userId, k -> new HashMap<>()).put(paqueteId, estado);
        }
    }

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
        try (Scanner scanner = new Scanner(file)) {
            String dataP = (scanner.nextLine().split(","))[1];
            int gInt = Integer.parseInt((scanner.nextLine().split(","))[1]);
            g = BigInteger.valueOf(gInt);
            String pCadena = dataP.replace(":", "");

            p = new BigInteger(hexToString(pCadena));

            Random random = new Random();
            x = new BigInteger(p.subtract(BigInteger.ONE).bitLength(), random);

            gx = g.modPow(x, BigInteger.TEN);
            y = gx.mod(p);
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }
    }

    @Override
    public void run() {
        loadKeys();
        System.out.println("Servidor comienza y espera en el puerto " + PORT);
        try (ServerSocket serverSocket = new ServerSocket(PORT, 1000000000)) {
            while (true) {
                try (Socket clientSocket = serverSocket.accept();
                        ObjectOutputStream out = new ObjectOutputStream(clientSocket.getOutputStream());
                        ObjectInputStream in = new ObjectInputStream(clientSocket.getInputStream())) {

                    String initMessage = (String) in.readObject();
                    byte[] reto = (byte[]) in.readObject();

                    Long startTime = System.nanoTime();
                    Cipher cipher1 = Cipher.getInstance("RSA");
                    cipher1.init(Cipher.DECRYPT_MODE, privada_servidor);
                    byte[] Rta = cipher1.doFinal(reto);
                    this.TimeGenerarConsulta += System.nanoTime() - startTime;

                    out.writeObject(Rta);

                    String Mensaje = (String) in.readObject();

                    generarLlave();

                    out.writeObject(g);
                    out.writeObject(p);
                    out.writeObject(gx);

                    Signature firma = Signature.getInstance("SHA1withRSA");
                    String msgConcat = String.join(g.toString(), p.toString(), gx.toString());
                    firma.initSign(privada_servidor);
                    firma.update(msgConcat.getBytes());
                    out.writeObject(firma.sign());

                    Mensaje = (String) in.readObject();

                    gy = (BigInteger) in.readObject();
                    gyx = gy.modPow(x, BigInteger.TEN);
                    BigInteger secretKey = gyx.mod(p);

                    MessageDigest sha512 = MessageDigest.getInstance("SHA-512");
                    byte[] hash = sha512.digest(secretKey.toString().getBytes());
                    k_ab1 = Arrays.copyOfRange(hash, 0, 32);
                    k_ab2 = Arrays.copyOfRange(hash, 32, hash.length);

                    SecureRandom random = new SecureRandom();
                    byte[] iv = new byte[16];
                    random.nextBytes(iv);
                    out.writeObject(iv);

                    llave_simetrica = new SecretKeySpec(k_ab1, "AES");

                    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                    cipher.init(Cipher.DECRYPT_MODE, llave_simetrica, new IvParameterSpec(iv));
                    ArrayList<byte[]> UIDYHash = (ArrayList<byte[]>) in.readObject();
                    byte[] uid_dec = cipher.doFinal(UIDYHash.get(0));
                    uid = new String(uid_dec);

                    paquete_id = new String(cipher.doFinal((byte[]) in.readObject()));
                    int estado = consultarEstado(uid, paquete_id);
                    out.writeObject(estadoToTexto(estado).getBytes());
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private int consultarEstado(String uid, String paquete_id) {
        return tablaPaquetes.getOrDefault(uid, new HashMap<>()).getOrDefault(paquete_id, DESCONOCIDO);
    }

    private String estadoToTexto(int estado) {
        switch (estado) {
            case ENOFICINA:
                return "ENOFICINA";
            case RECOGIDO:
                return "RECOGIDO";
            case ENCLASIFICACION:
                return "ENCLASIFICACION";
            case DESPACHADO:
                return "DESPACHADO";
            case ENENTREGA:
                return "ENENTREGADO";
            default:
                return "DESCONOCIDO";
        }
    }

    public void generateKeys() {
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(1024);
            KeyPair pair = keyGen.generateKeyPair();
            privada_servidor = pair.getPrivate();
            publica_servidor = pair.getPublic();

            // Guardar clave pública en archivo
            try (BufferedWriter bwPub = new BufferedWriter(new FileWriter("server_public_key.txt"))) {
                bwPub.write(Base64.getEncoder().encodeToString(publica_servidor.getEncoded()));
            }

            // Guardar clave privada en archivo
            try (BufferedWriter bwPriv = new BufferedWriter(new FileWriter("server_private_key.txt"))) {
                bwPriv.write(Base64.getEncoder().encodeToString(privada_servidor.getEncoded()));
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void loadKeys() {
        try {
            // Cargar clave pública
            try (BufferedReader br = new BufferedReader(new FileReader("server_public_key.txt"))) {
                String publicKeyStr = br.readLine();
                byte[] publicBytes = Base64.getDecoder().decode(publicKeyStr);
                KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                publica_servidor = keyFactory.generatePublic(new X509EncodedKeySpec(publicBytes));
            }

            // Cargar clave privada
            try (BufferedReader br = new BufferedReader(new FileReader("server_private_key.txt"))) {
                String privateKeyStr = br.readLine();
                byte[] privateBytes = Base64.getDecoder().decode(privateKeyStr);
                KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                privada_servidor = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privateBytes));
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
