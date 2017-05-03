package cliente;

/**
 * CASO 2 INFRACOMP
 * REALIZADO POR:
 * JULIÁN BERMUDEZ - 201519648
 * SEBASTIAN PRIETO - 201426358
 */

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Random;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;

public class Cliente {

	private static KeyPair keyPair;
	private static SecretKey ls;
	private static X509Certificate certClient;
	private static X509Certificate certServer;
	private static Socket socketCliente;
	private static PrintWriter output;
	private static BufferedReader input;
	private static BufferedReader stdIn;
	private static InputStream lineaEntrada;
	private static String retoConj[];
	private static String fromServer;
	private static String fromUser;

	private static final String PARARETO = "RSA";
	private static final String PARALLAVE = "AES";
	private static final String PARADIGEST = "HMACSHA256";

	private static CryptoDecrypto cryptoClase;

	private class CryptoDecrypto {

		public static final String RSA = "RSA";
		public static final String HMACSHA256 = "HMACSHA256";
		public static final String AES = "AES";

		public CryptoDecrypto() {
		}

		public byte[] symmetricEncryption(byte[] msg, Key key, String algo)
				throws IllegalBlockSizeException, BadPaddingException,
				InvalidKeyException, NoSuchAlgorithmException,
				NoSuchPaddingException {
			algo = String.valueOf(algo)
					+ (algo.equals("DES") || algo.equals("AES") ? "/ECB/PKCS5Padding"
							: "");
			Cipher decifrador = Cipher.getInstance(algo);
			decifrador.init(1, key);
			return decifrador.doFinal(msg);
		}

		public byte[] symmetricDecryption(byte[] msg, Key key, String algo)
				throws IllegalBlockSizeException, BadPaddingException,
				InvalidKeyException, NoSuchAlgorithmException,
				NoSuchPaddingException {
			algo = String.valueOf(algo)
					+ (algo.equals("DES") || algo.equals("AES") ? "/ECB/PKCS5Padding"
							: "");
			Cipher decifrador = Cipher.getInstance(algo);
			decifrador.init(2, key);
			return decifrador.doFinal(msg);
		}

		public byte[] asymmetricEncryption(byte[] msg, Key key, String algo)
				throws IllegalBlockSizeException, BadPaddingException,
				InvalidKeyException, NoSuchAlgorithmException,
				NoSuchPaddingException {
			Cipher decifrador = Cipher.getInstance(algo);
			decifrador.init(1, key);
			return decifrador.doFinal(msg);
		}

		public byte[] asymmetricDecryption(byte[] msg, Key key, String algo)
				throws NoSuchAlgorithmException, NoSuchPaddingException,
				InvalidKeyException, IllegalBlockSizeException,
				BadPaddingException {
			Cipher decifrador = Cipher.getInstance(algo);
			decifrador.init(2, key);
			return decifrador.doFinal(msg);
		}

		public byte[] hmacDigest(byte[] msg, Key key, String algo)
				throws NoSuchAlgorithmException, InvalidKeyException,
				IllegalStateException, UnsupportedEncodingException {
			Mac mac = Mac.getInstance(algo);
			mac.init(key);
			byte[] bytes = mac.doFinal(msg);
			return bytes;
		}

		public boolean verificarIntegridad(byte[] msg, Key key, String algo,
				byte[] hash) throws Exception {
			byte[] nuevo = hmacDigest(msg, key, algo);
			if (nuevo.length != hash.length) {
				return false;
			}
			int i = 0;
			while (i < nuevo.length) {
				if (nuevo[i] != hash[i]) {
					return false;
				}
				++i;
			}
			return true;
		}
	}

	public Cliente() {
		try {
			inicializar();
		} catch (UnknownHostException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		generarLlaves();
	}
	
	private void inicializar() throws UnknownHostException, IOException {
		socketCliente = new Socket();
		socketCliente.connect(new InetSocketAddress("172.24.42.120", 8080));
		stdIn = new BufferedReader(new InputStreamReader(System.in));
		lineaEntrada = socketCliente.getInputStream();
		input = new BufferedReader(new InputStreamReader(lineaEntrada));
		output = new PrintWriter(socketCliente.getOutputStream(), true);
		cryptoClase = new CryptoDecrypto();
		retoConj = new String[2];
	}
	
	
	
	public void inicioSesion() throws IOException {
		
//		System.out.print("Escriba el mensaje para el inicio de sesión: ");
		String rtaUser = "HOLA";

		if (rtaUser.equals("-1") || rtaUser.equalsIgnoreCase("FIN") || rtaUser == null) {
			System.out.println("Error al escribir la linea de entrada");
			fin();
		}

		fromUser = rtaUser;
		
		/**
		System.out.println("Rta Client: " + fromUser);
		*/
		
		output.println(fromUser);

		fromServer = input.readLine();
		System.out.println("Rta Server: " + fromServer);

		if (!fromServer.equals("OK")) {
			System.out.println("RESPUESTA ERROR DEL SERVIDOR");
			fin();
		}

		fromUser = "ALGORITMOS:AES:RSA:HMACSHA256";
		
		/**
		System.out.println("Rta Client: " + fromUser);
		*/
		
		output.println(fromUser);

		fromServer = input.readLine();

		if (!fromServer.equals("OK")) {
			System.out.println("RESPUESTA ERROR DEL SERVIDOR");
			fin();
		}
		
		/**
		System.out.println("Rta Server: " + fromServer);
		*/
		
		generarCertificado();

		try {
			imprimircertificado(certClient);
			
			/**
			System.out.println("Rta Client: CERTIFICADO CLIENTE");
			*/
			
		} catch (IOException e) {
			System.out.println("ERROR AL IMPRIMIR CERTIFICADO");
			e.getStackTrace();
			fin();
		}

		certServer = leerCertificado();
		if (certServer == null) {
			System.out.println("ERROR LEYENDO CERTIFICADO DEL SERVIDOR");
			fin();
		}
		
		/**
		System.out.println("Rta Server: CERTIFICADO SERVIDOR");
		*/
		
	}
	
	public void authServidor() throws IOException {

		retoConj = generarReto();

		output.println((retoConj[1]));

		System.out.println("Rta Client: RETO ENVIADO");

		fromServer = input.readLine();
		fromServer = input.readLine();

		if (fromServer.equals("ERROR") || fromServer == null
				|| fromServer.equals("")) {
			System.out.println("ERRROR AL RECIBIR RETO RESUELTO DEL SERVIDOR");
			fin();
		}

		System.out.println("Rta server: RTA RETO CLIENTE");
		fromUser = comprobarReto(fromServer);

		if (fromUser.equals("ERROR")) {
			System.out.println("ERROR: RETO NO RESUELTO CORRECTAMENTE");
			fin();
		}
		
		output.println(fromUser);
		System.out.println("Rta Client: " + fromUser);
		
	}
	
	public void authCliente() throws IOException {
		
		fromServer = input.readLine();
		System.out.println("Rta server: RETO SERVER");

		fromUser = resolverReto(fromServer);
		output.println(fromUser);
		System.out.println("Rta Cliente: RTA RETO SERVER");
		
		fromServer = input.readLine();

		if (fromServer.equals("ERROR") || fromServer.equals("") || fromServer.equals("-1")) {
			System.out.println("ERROR, SE ESPERABA LA LLAVE SIMÉTRICA");
		}

		try {
			ls = obtenerLlaveSim(fromServer);
		} catch (Exception e) {
			System.out.println("ERROR AL OBTENER LA LLAVE SIMÉTRICA");
			fin();
		}
		
	}
	
	public void realizarConsulta(String consulta) {
		
		System.out.println("Rta Client: CONSULTA... " + consulta);

		try {
			fromUser = generarConsulta(consulta);			
		} catch (InvalidKeyException | NoSuchAlgorithmException
				| IllegalStateException | IllegalBlockSizeException | BadPaddingException
				| NoSuchPaddingException | IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			fin();
		}
		
		output.println(fromUser);
		
		try {
			fromServer = input.readLine();
		} catch (IOException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		
		try {
			fromUser = leerRtaConsulta(fromServer);
		} catch (InvalidKeyException | IllegalBlockSizeException
				| BadPaddingException | NoSuchAlgorithmException
				| NoSuchPaddingException | IllegalStateException | UnsupportedEncodingException e) {
			System.out.println("ERROR AL LEER LA RESPUESTA A LA CONSULTA");
			e.printStackTrace();
		}
		
		output.println(fromUser);
		
	}
	
//	public static void main(String[] args) throws IOException {
//		Cliente c = new Cliente();
//		
//		c.inicioSesion();
//		c.authServidor();
//		c.authCliente();
//		c.realizarConsulta("2015");
//		fin();
//	}

	public static byte[] decodificar(String ss) {
		byte[] ret = new byte[ss.length() / 2];
		int i = 0;
		while (i < ret.length) {
			ret[i] = (byte) Integer.parseInt(ss.substring(i * 2, (i + 1) * 2),
					16);
			++i;
		}
		return ret;
	}

	private static String leerRtaConsulta(String rtaString) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalStateException, UnsupportedEncodingException {
		
		String[] partes = rtaString.split(":");

		byte[] rtaNoString = toByteArray(partes[0]);
		byte[] digestNoString = toByteArray(partes[1]);

		byte[] rtaDes = cryptoClase.symmetricDecryption(rtaNoString, ls, PARALLAVE);
		byte[] digestDes = cryptoClase.symmetricDecryption(digestNoString, ls, PARALLAVE);

		if (noAlterado(rtaDes, digestDes)) {
			System.out.println("Rta Server: " + new String(rtaDes));
			return "OK";
		} else
			return "ERROR";
	}

	private static boolean noAlterado(byte[] rtaDes, byte[] digestDes)
			throws InvalidKeyException, NoSuchAlgorithmException,
			IllegalStateException, UnsupportedEncodingException {

		byte[] digestPrueba = cryptoClase.hmacDigest(rtaDes, ls, PARADIGEST);

		if (digestPrueba.length != digestDes.length)
			return false;

		else {

			for (int i = 0; i < digestDes.length; i++) {
				if (digestDes[i] != digestPrueba[i])
					return false;
			}

			return true;
		}
	}

	private static String generarConsulta(String consulta)
			throws InvalidKeyException, NoSuchAlgorithmException,
			IllegalStateException, UnsupportedEncodingException,
			IllegalBlockSizeException, BadPaddingException,
			NoSuchPaddingException {
		byte[] consultaNoString = consulta.getBytes();
		byte[] digestivo = cryptoClase.hmacDigest(consultaNoString, ls,
				PARADIGEST);
		byte[] digestCrip = cryptoClase.symmetricEncryption(digestivo, ls,
				PARALLAVE);
		byte[] consultaEncriptada = cryptoClase.symmetricEncryption(
				consultaNoString, ls, PARALLAVE);
		String rta = toHexString(consultaEncriptada) + ":"
				+ toHexString(digestCrip);
		return rta;
	}

	private static SecretKey obtenerLlaveSim(String llaveHex)
			throws InvalidKeyException, NoSuchAlgorithmException,
			NoSuchPaddingException, IllegalBlockSizeException,
			BadPaddingException {
		byte[] llaveNoHex = toByteArray(llaveHex);
		return descifrar(llaveNoHex);
	}

	public static SecretKey descifrar(byte[] cipheredText)
			throws NoSuchAlgorithmException, NoSuchPaddingException,
			InvalidKeyException, IllegalBlockSizeException, BadPaddingException {

		Cipher decifrador = Cipher.getInstance(PARARETO);
		decifrador.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
		byte[] llaveDecifrada = decifrador.doFinal(cipheredText);

		SecretKeySpec llaveRecibida = new SecretKeySpec(llaveDecifrada,
				PARALLAVE);
		return llaveRecibida;

	}

	private static String resolverReto(String reto) {
		String rta = "";
		byte[] reto2NoHex = decodificar(reto);
		try {
			byte[] rts2Desc = cryptoClase.asymmetricDecryption(reto2NoHex,
					keyPair.getPrivate(), PARARETO);
			byte[] rts2Cifrado = cryptoClase.asymmetricEncryption(rts2Desc,
					certServer.getPublicKey(), PARARETO);
			rta = toHexString(rts2Cifrado);
		} catch (InvalidKeyException | NoSuchAlgorithmException
				| NoSuchPaddingException | IllegalBlockSizeException
				| BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return rta;
	}

	public void fin() {

		try {
			input.close();
			output.close();
			stdIn.close();
			socketCliente.close();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

	}

	private static String comprobarReto(String servRetoRta) {
		String rta = "ERROR";

		try {
			byte[] retoRtaBytes = toByteArray(servRetoRta);
			byte[] retoRtaSinCifrar = cryptoClase.asymmetricDecryption(retoRtaBytes, keyPair.getPrivate(), PARARETO);
			String retoRtaString = new String(retoRtaSinCifrar);

			if (retoRtaString.equalsIgnoreCase(retoConj[0]))
				rta = "OK";
		}
		catch (InvalidKeyException | NoSuchAlgorithmException
				| NoSuchPaddingException | IllegalBlockSizeException
				| BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		return rta;

	}

	private static void generarCertificado() {
		try {
			certClient = Certificado.generateV3Certificate(keyPair);
		} catch (Exception e) {
			System.out.println("fallo al generar el certificado");
			e.printStackTrace();
		}
	}

	private static String[] generarReto() {

		try {
			String retos[] = new String[2];
			Long semilla = 5678L;
			Random random = new Random(semilla);

			byte[] reto = "000000".getBytes();

			random.nextBytes(reto);

			String ret = new String(reto);
			retos[0] = ret;
			byte[] retoCifrado = cryptoClase.asymmetricEncryption(reto,
					certServer.getPublicKey(), PARARETO);
			retos[1] = toHexString(retoCifrado);

			return retos;
		} catch (NumberFormatException | InvalidKeyException
				| IllegalBlockSizeException | BadPaddingException
				| NoSuchAlgorithmException | NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return null;
		}

	}

	public static void imprimircertificado(X509Certificate certificado)
			throws IOException {
		StringWriter sw = new StringWriter();
		JcaPEMWriter pWrt = new JcaPEMWriter(sw);

		pWrt.writeObject(certificado);
		pWrt.flush();
		pWrt.close();

		String stringCert = sw.toString();
		output.println(stringCert);
	}

	public static X509Certificate leerCertificado() {
		X509Certificate cert = null;
		try {
			cert = (X509Certificate) CertificateFactory.getInstance("X.509")
					.generateCertificate(lineaEntrada);
		} catch (CertificateException e) {
			e.printStackTrace();
		}
		return cert;
	}

	public byte[] leerllave() throws IOException {
		String linea = input.readLine();
		linea = input.readLine();
		byte[] llaveSimServidor = toByteArray(linea);
		return llaveSimServidor;
	}

	public static String toHexString(byte[] array) {
		return DatatypeConverter.printHexBinary(array);
	}

	public static byte[] toByteArray(String s) {
		return DatatypeConverter.parseHexBinary(s);
	}

	private static void generarLlaves() {

		try {
			KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
			gen.initialize(1024, new SecureRandom());
			keyPair = gen.generateKeyPair();

			Security.addProvider(new BouncyCastleProvider());
			KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "BC");
			keyGen.initialize(1024);
			keyPair = keyGen.generateKeyPair();

		}

		catch (NoSuchAlgorithmException | NoSuchProviderException e) {
			System.out.println("fallo al generar las llaves");
			e.printStackTrace();
		}
	}

}
