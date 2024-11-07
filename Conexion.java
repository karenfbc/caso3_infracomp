import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;
import java.util.concurrent.BrokenBarrierException;
import java.util.concurrent.CyclicBarrier;
import java.io.File;
import java.io.IOException;

public class Conexion {
    private static Servidor servidor;

    public static void main(String[] args) throws InterruptedException, BrokenBarrierException {
        servidor = new Servidor();
        Scanner scanner = new Scanner(System.in);

        while (true) {
            System.out.println("Seleccione una opción:");
            System.out.println("1. Generar las llaves y almacenarlas en archivos.");
            System.out.println("2. Ejecutar el protocolo.");
            System.out.println("0. Salir.");
            String opcion = scanner.nextLine();

            switch (opcion) {
                case "1":
                    generarLlavesServidor();
                    break;

                case "2":
                    seleccionarEscenario(scanner);
                    break;

                case "0":
                    System.out.println("Saliendo del sistema.");
                    scanner.close();
                    return;

                default:
                    System.out.println("Opción no válida. Intente de nuevo.");
                    break;
            }
        }
    }

    private static void generarLlavesServidor() {
        System.out.println("Generando las llaves asimétricas del servidor...");
        servidor.generateKeys();

        // Mover la llave pública a un directorio accesible
        File publicKeyFile = new File("server_public_key.txt");
        File accessibleDirectory = new File("public_keys");
        if (!accessibleDirectory.exists()) {
            accessibleDirectory.mkdir();
        }

        File publicKeyDestination = new File(accessibleDirectory, publicKeyFile.getName());
        if (publicKeyFile.renameTo(publicKeyDestination)) {
            System.out.println("Llave pública guardada en: " + publicKeyDestination.getAbsolutePath());
            System.out.println("Llave privada guardada en el servidor (no accesible públicamente).");
        } else {
            System.out.println("Error al mover la llave pública al directorio accesible.");
        }
    }

    private static void seleccionarEscenario(Scanner scanner) throws InterruptedException, BrokenBarrierException {
        System.out.println("Seleccione el escenario:");
        System.out.println("1. Servidor y Cliente Iterativos (32 consultas secuenciales).");
        System.out.println("2. Servidor y Cliente con Delegados Concurrentes (4, 8, 32 delegados).");
        String opcion = scanner.nextLine();

        switch (opcion) {
            case "1":
                ejecutarEscenarioIterativo(scanner);
                break;

            case "2":
                ejecutarEscenarioConcurrente(scanner);
                break;

            default:
                System.out.println("Opción no válida. Intente de nuevo.");
                break;
        }
    }

    private static void ejecutarEscenarioIterativo(Scanner scanner) throws InterruptedException {
        servidor.start();
        List<Cliente> ListaClientes = new ArrayList<>();
    
        // Espera inicial para asegurarse de que el servidor esté corriendo
        try {
            Thread.sleep(1000);
        } catch (InterruptedException e) {
            System.out.println("Interrupción durante la espera inicial.");
        }
    
        while (true) {
            System.out.println("Ingrese el número de clientes que desea correr (ej. 1, 2, 4, etc.) o '0' para volver al menú principal:");
            String input = scanner.nextLine();
    
            servidor.setTimeDescrifarConsulta(0L);
            servidor.setTimeGenerarConsulta(0L);
            servidor.setTimeVerificarCodigoAutenticacion(0L);
    
            if (input.equalsIgnoreCase("0")) {
                System.out.println("Volviendo al menú principal.");
                break;
            }
    
            try {
                int numClientes = Integer.parseInt(input);
    
                // Crear y lanzar los clientes secuenciales
                for (int i = 0; i < numClientes; i++) {
                    Cliente cliente = new Cliente(i + 1, null); // No se necesita CyclicBarrier
                    ListaClientes.add(cliente);
    
                    // Ejecutar 32 consultas de manera iterativa
                    cliente.ejecutar32Consultas(); // Asegúrate de tener un método que ejecute 32 consultas secuenciales
                }
    
                // Calcular los tiempos promedios de cada operación
                long totalVerificarFirma = 0;
                long totalGenerarGY = 0;
                long totalCifrarConsulta = 0;
                long totalGenerarCodigoAutenticacion = 0;
    
                for (Cliente cliente : ListaClientes) {
                    totalVerificarFirma += cliente.getTiempoVerificarFirma();
                    totalGenerarGY += cliente.getTiempoGenerarGY();
                    totalCifrarConsulta += cliente.getTiempoCifrarConsulta();
                    totalGenerarCodigoAutenticacion += cliente.getTiempoGenerarCodigoAutenticacion();
                }
    
                long promedioVerificarFirma = totalVerificarFirma / ListaClientes.size();
                long promedioGenerarGY = totalGenerarGY / ListaClientes.size();
                long promedioCifrarConsulta = totalCifrarConsulta / ListaClientes.size();
                long promedioGenerarCodigoAutenticacion = totalGenerarCodigoAutenticacion / ListaClientes.size();
    
                System.out.println("TIEMPOS PROMEDIO DE CLIENTES: \n");
                System.out.println("Tiempo promedio verificar la firma: " + promedioVerificarFirma + " nanosegundos");
                System.out.println("Tiempo promedio calcular G^y: " + promedioGenerarGY + " nanosegundos");
                System.out.println("Tiempo promedio cifrar consulta: " + promedioCifrarConsulta + " nanosegundos");
                System.out.println("Tiempo promedio generar código de autenticación: "
                        + promedioGenerarCodigoAutenticacion + " nanosegundos\n");
    
                System.out.println("TIEMPOS DEL SERVIDOR: \n");
                System.out.println("Tiempo generar la firma: " + servidor.getTimeGenerarConsulta() + " nanosegundos");
                System.out.println("Tiempo descifrar la consulta: " + servidor.getTimeDescrifarConsulta() + " nanosegundos");
                System.out.println("Tiempo verificar el código de autenticación: "
                        + servidor.getTimeVerificarCodigoAutenticacion() + " nanosegundos\n");
                System.out.println("Todos los clientes han completado sus tareas.");
            } catch (NumberFormatException e) {
                System.out.println("Por favor, ingrese un número válido de clientes o '0' (cero) para terminar.");
            }
        }
    }
    

    private static void ejecutarEscenarioConcurrente(Scanner scanner) throws InterruptedException, BrokenBarrierException {
        servidor.start();
        List<Cliente> ListaClientes = new ArrayList<>();

        // Espera inicial para asegurar que el servidor esté corriendo
        try {
            Thread.sleep(1000);
        } catch (InterruptedException e) {
            System.out.println("Interrupción durante la espera inicial.");
        }
        while (true) {
            System.out.println(
                    "Por favor ingrese Ingrese el número de delegados (4, 8, 32) o escriba '0' (cero) para volver al menú principal:");
            String input = scanner.nextLine();

            

            // Resetear los tiempos en el servidor
            servidor.setTimeDescrifarConsulta(0L);
            servidor.setTimeGenerarConsulta(0L);
            servidor.setTimeVerificarCodigoAutenticacion(0L);

            if (input.equalsIgnoreCase("0")) {
                System.out.println("Volviendo al menú principal.");
                break;
            }

            try {
                int numClientes = Integer.parseInt(input);
                final CyclicBarrier barrier = new CyclicBarrier(numClientes + 1);

                // Crear y lanzar los hilos de cliente
                for (int i = 0; i < numClientes; i++) {
                    Cliente cliente = new Cliente(i + 1, barrier);
                    ListaClientes.add(cliente);
                    cliente.start();
                }

                // Esperar a que todos los clientes completen sus tareas
                barrier.await();

                long totalVerificarFirma = 0;
                long totalGenerarGY = 0;
                long totalCifrarConsulta = 0;
                long totalGenerarCodigoAutenticacion = 0;

                for (Cliente cliente : ListaClientes) {
                    totalVerificarFirma += cliente.getTiempoVerificarFirma();
                    totalGenerarGY += cliente.getTiempoGenerarGY();
                    totalCifrarConsulta += cliente.getTiempoCifrarConsulta();
                    totalGenerarCodigoAutenticacion += cliente.getTiempoGenerarCodigoAutenticacion();
                }

                long promedioVerificarFirma = totalVerificarFirma / ListaClientes.size();
                long promedioGenerarGY = totalGenerarGY / ListaClientes.size();
                long promedioCifrarConsulta = totalCifrarConsulta / ListaClientes.size();
                long promedioGenerarCodigoAutenticacion = totalGenerarCodigoAutenticacion / ListaClientes.size();

                System.out.println("TIEMPOS PROMEDIO DE CLIENTES: \n");
                System.out.println("Tiempo promedio verificar la firma: " + promedioVerificarFirma + " nanosegundos");
                System.out.println("Tiempo promedio calcular G^y: " + promedioGenerarGY + " nanosegundos");
                System.out.println("Tiempo promedio cifrar consulta: " + promedioCifrarConsulta + " nanosegundos");
                System.out.println("Tiempo promedio generar codigo de autenticación: "
                        + promedioGenerarCodigoAutenticacion + " nanosegundos\n");

                System.out.println("TIEMPOS DEL SERVIDOR: \n");
                System.out.println("Tiempo generar la firma: " + servidor.getTimeGenerarConsulta() + " nanosegundos");
                System.out.println(
                        "Tiempo descifrar la consulta: " + servidor.getTimeDescifrarConsulta() + " nanosegundos");
                System.out.println("Tiempo verificar el código de autenticacion: "
                        + servidor.getTimeVerificarCodigoAutenticacion() + " nanosegundos\n");
                System.out.println("Todos los clientes han completado sus tareas. Puede ingresar otro caso o salir.");
            } catch (NumberFormatException e) {
                System.out.println("Por favor, ingrese un número válido de usuarios o '0' (cero) para terminar.");
            }
        }
    }
}
