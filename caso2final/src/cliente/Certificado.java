package cliente;

import java.math.BigInteger;
import java.security.*;
import java.security.cert.*;
import java.util.Date;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Random;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import sun.security.x509.*;

public class Certificado {

	public static X509Certificate generateV3Certificate(KeyPair pair) throws Exception {
		PublicKey subPub = pair.getPublic();
		PrivateKey issPriv = pair.getPrivate();
		PublicKey issPub = pair.getPublic();
		JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
		JcaX509v3CertificateBuilder v3CertGen = new JcaX509v3CertificateBuilder(new X500Name("CN=0.0.0.0, OU=None, O=None, L=None, C=None"), new BigInteger(128, new SecureRandom()), new Date(System.currentTimeMillis()), new Date(System.currentTimeMillis() + 8640000000L), new X500Name("CN=0.0.0.0, OU=None, O=None, L=None, C=None"), subPub);
		v3CertGen.addExtension(X509Extension.subjectKeyIdentifier, false, (ASN1Encodable)extUtils.createSubjectKeyIdentifier(subPub));
		v3CertGen.addExtension(X509Extension.authorityKeyIdentifier, false, (ASN1Encodable)extUtils.createAuthorityKeyIdentifier(issPub));
		return new JcaX509CertificateConverter().setProvider("BC").getCertificate(v3CertGen.build(new JcaContentSignerBuilder("MD5withRSA").setProvider("BC").build(issPriv)));
	}

	public static void imprimircert(X509Certificate certificado)
	{
		String s = certificado.toString();
		String[] array = s.split("\n");
		for (int i = 0; i < array.length; i++) {
			String temp = array[i];
			temp.replace("\n", "");
			System.out.println(temp);
		}
	}

	public static void main(String[] args) throws Exception {
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

		KeyPair pair = generateRSAKeyPair();
		X509Certificate cert = generateV3Certificate(pair);
		cert.checkValidity(new Date());
		cert.verify(cert.getPublicKey());
		imprimircert(cert);
		//System.out.println(cert.toString());
	}
	public static KeyPair generateRSAKeyPair() throws Exception {
		KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA", "BC");
		kpGen.initialize(1024, new SecureRandom());
		return kpGen.generateKeyPair();
	}

}
