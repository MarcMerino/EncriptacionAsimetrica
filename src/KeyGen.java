import java.io.BufferedReader;
import java.io.FileOutputStream;
import java.io.InputStreamReader;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.util.Date;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;

public class KeyGen implements Constants {

	public static void main(String[] args) throws Exception {
		// Generamos las claves publica/privada 
        SecureRandom sr = new SecureRandom(); 
        sr.setSeed(new Date().getTime()); 
        
        System.out.println("Generando claves..."); 
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA"); 
        kpg.initialize(TAMANO_CLAVE_RSA, sr); 
        
        KeyPair par_claves = kpg.generateKeyPair(); 
        System.out.println("Claves generadas"); 
        
        // Generamos el fichero de la clave publica 
        System.out.print("Indique fichero para la clave publica:"); 
        
        BufferedReader teclado = new BufferedReader(new InputStreamReader(System.in)); 
        
        String fichero_publica; 
        fichero_publica = teclado.readLine(); 
        
        FileOutputStream fos = new FileOutputStream(fichero_publica); 
        fos.write(par_claves.getPublic().getEncoded()); 
        fos.close(); 
        System.out.println("Fichero con clave publica generado"); 
        
        // Generamos el fichero de clave privada 
        System.out.print("Indique fichero para la clave privada:"); 
        String fichero_privada; 
        fichero_privada = teclado.readLine(); 
        System.out.print("La clave privada debe estar encriptada, indique password con la que encriptarla:"); 
        char[] password = teclado.readLine().toCharArray(); 
        
        // Encriptamos con un PBE 
        byte[] salt = new byte[TAMANO_SALT_BYTES]; 
        sr.nextBytes(salt); 
        PBEKeySpec clave_pbe = new PBEKeySpec(password); 
        SecretKey clave_secreta_pbe = SecretKeyFactory.getInstance("PBEWITHSHA1ANDRC2_40").generateSecret(clave_pbe); 
        PBEParameterSpec pbe_param = new PBEParameterSpec(salt, ITERACIONES_PBE); 
        Cipher cifrador_pbe = Cipher.getInstance("PBEWITHSHA1ANDRC2_40"); 
        cifrador_pbe.init(Cipher.ENCRYPT_MODE, clave_secreta_pbe,pbe_param); 
        byte[] clave_privada_cifrada = cifrador_pbe.doFinal(par_claves.getPrivate().getEncoded()); 
        fos = new FileOutputStream(fichero_privada); 
        fos.write(salt); 
        fos.write(clave_privada_cifrada); 
        
        fos.close(); 
        
        System.out.println("Fichero con clave privada generado"); 

	}

}
