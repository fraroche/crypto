package fr.si2m.socle.security.crypt.symetric;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;

import org.apache.commons.codec.binary.Base64;

public class Cipherer {

	private static final String wrappedKey="K4SwakrSHux4JhkBvJVgVvaMPpRm7M1o";
	private static final String pwd ="toto";
	private static final byte[] salt = "my8lSalt".getBytes();

	private final Key aesKey;

	public Cipherer(final String pPassword, final byte[] pSalt) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {
		this.aesKey = getAesKey(pPassword, pSalt);
	}

	private static Key getAesKey(final String pPassword, final byte[] pSalt) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {
		String TRANSFORMATION_TYPE = "PBEWithMD5AndDES";

		// generation de la clef enveloppante
		SecretKeyFactory kf = SecretKeyFactory.getInstance(TRANSFORMATION_TYPE);
		KeySpec keySpec = new PBEKeySpec(pPassword.toCharArray());
		Key clePourChiffrer = kf.generateSecret(keySpec);
		//			System.out.println("cle de chiffre: " + bytesToHex(clePourChiffrer.getEncoded()));

		// generation du chiffreur de l'enveloppe
		AlgorithmParameterSpec params = new PBEParameterSpec(salt, 1000);
		Cipher cipher = Cipher.getInstance(TRANSFORMATION_TYPE);
		cipher.init(Cipher.UNWRAP_MODE, clePourChiffrer, params);

		// unwrap de la clef
		Key key = cipher.unwrap(Base64.decodeBase64(wrappedKey.getBytes()), "AES", Cipher.SECRET_KEY);
		return key;
	}

	public String aesEncode(final String pClearMsg) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		Cipher cipher = Cipher.getInstance("AES");
		cipher.init(Cipher.ENCRYPT_MODE, this.aesKey);
		String encryptedMsg = new String(Base64.encodeBase64(cipher.doFinal(pClearMsg.getBytes())));
		return encryptedMsg;
	}

	public String aesDecode(final String pCrytpedMsg) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		Cipher cipher = Cipher.getInstance("AES");
		cipher.init(Cipher.DECRYPT_MODE, this.aesKey);
		String cleardMsg = new String(cipher.doFinal(Base64.decodeBase64(pCrytpedMsg.getBytes())));
		return cleardMsg;
	}

	public static void main(String[] args) {
		byte[] pass = Base64.decodeBase64(wrappedKey.getBytes());
		for (int i = 0; i < pass.length; i++) {
			System.out.print(((i==0?"[":", ")+pass[i]+(i==(pass.length-1)?"]\n":"")));
		}

		try {
			getAesKey(pwd, salt);
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		String msg = "Foo Bar open";
		System.out.println("Message: "+msg);
		Cipherer ciph;
		try {
			ciph = new Cipherer(pwd, salt);
			msg = ciph.aesEncode(msg);
			System.out.println("Encoded Msg: "+msg);
			msg = ciph.aesDecode(msg);
			System.out.println("Decoded Msg: "+msg);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
}
