package com.eletro7.security;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.security.cert.CertificateException;
import javax.security.cert.X509Certificate;

import org.bouncycastle.util.encoders.Base64;

public class BPagCipher {

	private static final String PUBLIC_KEY_CERTIFICATE = "BPagPublicKeyX509Certificate.crt";
	private static final String ENCRYPT_ALGORITHM = "RSA/ECB/PKCS1Padding";
	private static final String PROVIDER = "BC";

	private X509Certificate cert;
	private javax.crypto.Cipher cipher;

	public BPagCipher() {

		try {
			// Adiciona o provider
			Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

			// Instancia um X509Certificate a partir do certificado da BPag
			cert = X509Certificate.getInstance(getClass().getResourceAsStream(
					PUBLIC_KEY_CERTIFICATE));

			// Instancia um cifrador
			cipher = javax.crypto.Cipher.getInstance(ENCRYPT_ALGORITHM,
					PROVIDER);

		} catch (CertificateException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		}
	}

	/**
	 * Criptografa a string recebida com o algoritmo RSA e a chave publica do
	 * BPag.
	 * 
	 * @param aString
	 *            Texto a ser criptografado
	 * @return o texto criptografado
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
	public String encrypt(String aString) throws InvalidKeyException,
			IllegalBlockSizeException, BadPaddingException {

		// byte array para receber os bytes criptografados
		byte[] encryptedString = null;

		// inicializa o cifrador
		cipher.init(Cipher.ENCRYPT_MODE, cert.getPublicKey());

		// Cifra o texto e condifica para Base64
		encryptedString = Base64.encode(cipher.doFinal(aString.getBytes()));

		// Se o array de bytes não for nulo retorna como string
		if (encryptedString != null) {
			return new String(encryptedString);
		}

		// se houver falha na criptografia o retorno é null
		return null;
	}
}
