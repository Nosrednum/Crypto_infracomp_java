package Caso2;

import java.io.*;
import javax.crypto.*;
import java.net.Socket;
import java.util.Arrays;
import javax.xml.bind.DatatypeConverter;

/**
 * @author Anderson Barrag�n Agudelo	201719821
 * @author Sebastian D�az Mujica		201633171
 */
public class ClienteNoSeguro {

	/* ___Constantes de inicializaci�n de la comunicaci�n___ */
	static Socket servidor;
	static final  String 	URL		=  "localhost";
	static final  int 		PORT 	=	4321;
	static BufferedReader 	reader;
	static PrintWriter 		writer;

	/* ___Constantes de control de la aplicaci�n___ */
	static SecretKey secretKey;

	static final String HOLA = "HOLA", ALGORITMOS = "ALGORITMOS", OK = "OK", ERROR = "ERROR",
			ALGS = "AES", ALGA = "RSA", ALGHMAC = "HMACSHA512",
			RETO = "1234567890123456",cedula = "09876543", password = "contrasenhia";

	/** Ejecuci�n de la aplicaci�n */
	public static void main(String[] args) throws Exception {
		ClienteNoSeguro c = new ClienteNoSeguro();

		servidor = new Socket(URL, PORT);	//conexi�n con el servidor
		InputStreamReader isr = new InputStreamReader(servidor.getInputStream());
		reader = new BufferedReader(isr);
		writer = new PrintWriter(servidor.getOutputStream(), true);

		c.run(reader, writer);

		writer.close();
		reader.close();
		isr.close();
		servidor.close();
	}

	/** M�todo principal, maneja la comunicaci�n y los diversos m�todos*/
	public void run(BufferedReader bf, PrintWriter pw) throws Exception {

		secretKey = KeyGenerator.getInstance(ALGS).generateKey(); //Llave sim�trica

		cliente(HOLA);	//Env�a hola
		if (OK.equals(server())) {	//confima la recepci�n del HOLA

			cliente(ALGORITMOS + ":" + ALGS + ":" + ALGA + ":" + ALGHMAC);	// Env�a los algor�tmos a usar
			if (OK.equals(server())) {	//confirma la recepci�n de los algoritmos
				server("Certificado >>");
				cliente("llave sim�trica >>", DatatypeConverter.printBase64Binary(secretKey.getEncoded()));//env�a la llave sim�trica
				cliente(RETO);	//env�a el reto al servidor
				cliente(RETO.equals(server("Reto >>")) ? OK : ERROR); //recibe el reto del servidor
				cliente(cedula);	//env�a la c�dula
				cliente(password);	//env�a la contrase�a

				Mac hash = Mac.getInstance(ALGHMAC);
				hash.init(secretKey);

				String temp =new String();
				byte[] hval1 = hash.doFinal(DatatypeConverter.parseBase64Binary((temp=server("El valor obtenido es >>"))));//Realiza el hash a la informaci�n
				System.err.println("\tEl valor Obtenido es >> "+temp);
				byte[] hval2 = DatatypeConverter.parseBase64Binary(server());	 //hash enviado por el servidor para verificar el valor anterior

				cliente("Confirmaci�n del valor >>",(Arrays.equals(hval1, hval2))?OK:ERROR); //confirma la integridad del mensaje al servidor
			}
		}
	}

	/** Metodo de env�o de informaci�n al servidor */
	static void cliente(String complement, String message) {
		writer.println(message);
		System.out.println(" Cliente > " + complement + " " + message);
	}

	/** Metodo de env�o de informaci�n al servidor */
	static void cliente(String message) {
		writer.println(message);
		System.out.println(" Cliente > " + message);
	}

	/** M�todo de recepci�n de informaci�n del servidor */
	static String server(String complemetn) throws Exception {
		String ret = reader.readLine();
		System.out.println("- Server > " + complemetn + " " + ret);
		return ret;
	}

	/** M�todo de recepci�n de informaci�n del servidor */
	static String server() throws Exception {return server("");}
}
