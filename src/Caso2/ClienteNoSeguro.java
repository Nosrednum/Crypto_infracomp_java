package Caso2;

import java.io.*;
import javax.crypto.*;
import java.net.Socket;
import java.util.Arrays;
import javax.xml.bind.DatatypeConverter;

/**
 * @author Anderson Barragán Agudelo	201719821
 * @author Sebastian Díaz Mujica		201633171
 */
public class ClienteNoSeguro {

	/* ___Constantes de inicialización de la comunicación___ */
	static Socket servidor;
	static final  String 	URL		=  "localhost";
	static final  int 		PORT 	=	4321;
	static BufferedReader 	reader;
	static PrintWriter 		writer;

	/* ___Constantes de control de la aplicación___ */
	static SecretKey secretKey;

	static final String HOLA = "HOLA", ALGORITMOS = "ALGORITMOS", OK = "OK", ERROR = "ERROR",
			ALGS = "AES", ALGA = "RSA", ALGHMAC = "HMACSHA512",
			RETO = "1234567890123456",cedula = "09876543", password = "contrasenhia";

	/** Ejecución de la aplicación */
	public static void main(String[] args) throws Exception {
		ClienteNoSeguro c = new ClienteNoSeguro();

		servidor = new Socket(URL, PORT);	//conexión con el servidor
		InputStreamReader isr = new InputStreamReader(servidor.getInputStream());
		reader = new BufferedReader(isr);
		writer = new PrintWriter(servidor.getOutputStream(), true);

		c.run(reader, writer);

		writer.close();
		reader.close();
		isr.close();
		servidor.close();
	}

	/** Método principal, maneja la comunicación y los diversos métodos*/
	public void run(BufferedReader bf, PrintWriter pw) throws Exception {

		secretKey = KeyGenerator.getInstance(ALGS).generateKey(); //Llave simétrica

		cliente(HOLA);	//Envía hola
		if (OK.equals(server())) {	//confima la recepción del HOLA

			cliente(ALGORITMOS + ":" + ALGS + ":" + ALGA + ":" + ALGHMAC);	// Envía los algorítmos a usar
			if (OK.equals(server())) {	//confirma la recepción de los algoritmos
				server("Certificado >>");
				cliente("llave simétrica >>", DatatypeConverter.printBase64Binary(secretKey.getEncoded()));//envía la llave simétrica
				cliente(RETO);	//envía el reto al servidor
				cliente(RETO.equals(server("Reto >>")) ? OK : ERROR); //recibe el reto del servidor
				cliente(cedula);	//envía la cédula
				cliente(password);	//envía la contraseña

				Mac hash = Mac.getInstance(ALGHMAC);
				hash.init(secretKey);

				String temp =new String();
				byte[] hval1 = hash.doFinal(DatatypeConverter.parseBase64Binary((temp=server("El valor obtenido es >>"))));//Realiza el hash a la información
				System.err.println("\tEl valor Obtenido es >> "+temp);
				byte[] hval2 = DatatypeConverter.parseBase64Binary(server());	 //hash enviado por el servidor para verificar el valor anterior

				cliente("Confirmación del valor >>",(Arrays.equals(hval1, hval2))?OK:ERROR); //confirma la integridad del mensaje al servidor
			}
		}
	}

	/** Metodo de envío de información al servidor */
	static void cliente(String complement, String message) {
		writer.println(message);
		System.out.println(" Cliente > " + complement + " " + message);
	}

	/** Metodo de envío de información al servidor */
	static void cliente(String message) {
		writer.println(message);
		System.out.println(" Cliente > " + message);
	}

	/** Método de recepción de información del servidor */
	static String server(String complemetn) throws Exception {
		String ret = reader.readLine();
		System.out.println("- Server > " + complemetn + " " + ret);
		return ret;
	}

	/** Método de recepción de información del servidor */
	static String server() throws Exception {return server("");}
}
