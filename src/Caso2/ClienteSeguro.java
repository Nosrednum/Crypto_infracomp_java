package Caso2;

import java.io.*;
import javax.crypto.*;
import java.net.Socket;
import java.util.Arrays;
import java.security.Key;
import javax.xml.bind.DatatypeConverter;
import java.security.cert.X509Certificate;
import java.security.cert.CertificateFactory;

/**
 * @author Anderson Barragán Agudelo	201719821
 * @author Sebastian Díaz Mujica		201633171
 */
public class ClienteSeguro {

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
		ClienteSeguro c = new ClienteSeguro();

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

				CertificateFactory builder = CertificateFactory.getInstance("X.509");
				X509Certificate certificado = (X509Certificate) builder.generateCertificate(
						new ByteArrayInputStream(DatatypeConverter.parseBase64Binary(server("certificado >>"))));//crea el sertificado con la informai¿ción del servidor

				Cipher c = Cipher.getInstance(ALGA);
				c.init(Cipher.ENCRYPT_MODE, certificado.getPublicKey());

				cliente("llave simétrica >>", DatatypeConverter.printBase64Binary(c.doFinal(secretKey.getEncoded())));//envía la llave simétrica encriptada con la pública del servidor
				cliente(RETO);	//envía el reto al servidor
				cliente(((RETO.equals(descifrar(server("Reto encriptado >>"), secretKey))) ? OK : ERROR)); //recibe el reto cifrado del servidor, lo descifra y determina si la llave fue correctamente enviada
				cliente(cifrar(cedula));	//envía la cédula cifrada con la llave simétrica
				cliente(cifrar(password));	//envía la contraseña cifrada con la llave simétrica

				c.init(Cipher.DECRYPT_MODE, certificado.getPublicKey());
				Mac hash = Mac.getInstance(ALGHMAC);
				hash.init(secretKey);

				String temp =new String();
				byte[] hval1 = hash.doFinal(DatatypeConverter.parseBase64Binary((temp=descifrar(server("El valor obtenido (ENCRIPTADO) es >>"), secretKey))));//Realiza el hash a la información (que se desencripta) brindada por el servidor
				System.err.println("\tEl valor Obtenido decriptado es >> "+temp);
				byte[] hval2 = c.doFinal(DatatypeConverter.parseBase64Binary(server()));	 //decripta el hash eviado por el servidor para autenticar el servidor y además verificar el valor anterior

				cliente("Confirmación del valor >>",(Arrays.equals(hval1, hval2))?OK:ERROR); //confirma la integridad del mensaje al servidor
			}
		}
	}

	/** cifra el texto pasado con la llave especificada */
	static String cifrar(String texto, Key llave) throws Exception {
		while (texto.length() % 4 > 0)
			texto = "0" + texto;
		Cipher c = Cipher.getInstance(ALGS);
		c.init(Cipher.ENCRYPT_MODE, llave);
		return DatatypeConverter.printBase64Binary(c.doFinal(DatatypeConverter.parseBase64Binary(texto)));
	}

	/** cifra la información con la llave simétrica de la aplicación */
	static String cifrar(String texto) throws Exception {return cifrar(texto, secretKey);}

	/** descifra la información con la llave especificada */
	public static String descifrar(String texto, Key key) throws Exception {
		Cipher c = Cipher.getInstance(ALGS);
		c.init(Cipher.DECRYPT_MODE, key);
		return DatatypeConverter.printBase64Binary(c.doFinal(DatatypeConverter.parseBase64Binary(texto)));
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
