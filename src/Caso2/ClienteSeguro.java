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
 * @author Anderson Barrag�n Agudelo	201719821
 * @author Sebastian D�az Mujica		201633171
 */
public class ClienteSeguro {

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
		ClienteSeguro c = new ClienteSeguro();

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

				CertificateFactory builder = CertificateFactory.getInstance("X.509");
				X509Certificate certificado = (X509Certificate) builder.generateCertificate(
						new ByteArrayInputStream(DatatypeConverter.parseBase64Binary(server("certificado >>"))));//crea el sertificado con la informai�ci�n del servidor

				Cipher c = Cipher.getInstance(ALGA);
				c.init(Cipher.ENCRYPT_MODE, certificado.getPublicKey());

				cliente("llave sim�trica >>", DatatypeConverter.printBase64Binary(c.doFinal(secretKey.getEncoded())));//env�a la llave sim�trica encriptada con la p�blica del servidor
				cliente(RETO);	//env�a el reto al servidor
				cliente(((RETO.equals(descifrar(server("Reto encriptado >>"), secretKey))) ? OK : ERROR)); //recibe el reto cifrado del servidor, lo descifra y determina si la llave fue correctamente enviada
				cliente(cifrar(cedula));	//env�a la c�dula cifrada con la llave sim�trica
				cliente(cifrar(password));	//env�a la contrase�a cifrada con la llave sim�trica

				c.init(Cipher.DECRYPT_MODE, certificado.getPublicKey());
				Mac hash = Mac.getInstance(ALGHMAC);
				hash.init(secretKey);

				String temp =new String();
				byte[] hval1 = hash.doFinal(DatatypeConverter.parseBase64Binary((temp=descifrar(server("El valor obtenido (ENCRIPTADO) es >>"), secretKey))));//Realiza el hash a la informaci�n (que se desencripta) brindada por el servidor
				System.err.println("\tEl valor Obtenido decriptado es >> "+temp);
				byte[] hval2 = c.doFinal(DatatypeConverter.parseBase64Binary(server()));	 //decripta el hash eviado por el servidor para autenticar el servidor y adem�s verificar el valor anterior

				cliente("Confirmaci�n del valor >>",(Arrays.equals(hval1, hval2))?OK:ERROR); //confirma la integridad del mensaje al servidor
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

	/** cifra la informaci�n con la llave sim�trica de la aplicaci�n */
	static String cifrar(String texto) throws Exception {return cifrar(texto, secretKey);}

	/** descifra la informaci�n con la llave especificada */
	public static String descifrar(String texto, Key key) throws Exception {
		Cipher c = Cipher.getInstance(ALGS);
		c.init(Cipher.DECRYPT_MODE, key);
		return DatatypeConverter.printBase64Binary(c.doFinal(DatatypeConverter.parseBase64Binary(texto)));
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
