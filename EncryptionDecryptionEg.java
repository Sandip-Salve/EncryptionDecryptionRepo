package Simple;

import java.security.MessageDigest;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class EncryptionDecryptionEg {

	private static final String ALGORITHM = "AES";
	private static final String TRANSFORMATION = "AES/ECB/PKCS5Padding";
	private static final String secretKey = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890";
	
	public static String encryption(String input) {
		try {
			MessageDigest digest = MessageDigest.getInstance("SHA-256");
			digest.update(secretKey.substring(0,31).getBytes("UTF-8"));
			byte[] arr = new byte[32];
			System.arraycopy(digest.digest(), 0, arr, 0, arr.length);
			SecretKeySpec key = new SecretKeySpec(arr, ALGORITHM);
			Cipher cipher = Cipher.getInstance(TRANSFORMATION);
			cipher.init(Cipher.ENCRYPT_MODE, key);
			byte[] byteArr = cipher.doFinal(input.getBytes("UTF-8"));
			return Base64.getEncoder().encodeToString(byteArr);
		}catch(Exception ex) {
			System.out.println("Exception inside encryption : "+ex.getMessage());
		}
		return "";
	}
	public static String decryption(String input) {
		try {
			MessageDigest digest = MessageDigest.getInstance("SHA-256");
			digest.update(secretKey.substring(0,31).getBytes("UTF-8"));
			byte[] arr = new byte[32];
			System.arraycopy(digest.digest(), 0, arr, 0, arr.length);
			SecretKeySpec key = new SecretKeySpec(arr, ALGORITHM);
			Cipher cipher = Cipher.getInstance(TRANSFORMATION);
			cipher.init(Cipher.DECRYPT_MODE, key);
			byte[] byteArr = cipher.doFinal(Base64.getDecoder().decode(input));
			return new String(byteArr,"UTF-8");
		}catch(Exception ex) {
			System.out.println("Exception inside encryption : "+ex.getMessage());
		}
		return "";
	}
	public static void main(String[] args) {
		String encrypted = encryption("Testing");
		System.out.println(encrypted);
		String decrypted = decryption(encrypted);
		System.out.println(decrypted);
	}
}
