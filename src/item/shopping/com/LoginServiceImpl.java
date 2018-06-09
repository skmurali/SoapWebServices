package item.shopping.com;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.util.Properties;

import javax.crypto.Cipher;
import javax.jws.WebService;
import javax.jws.soap.SOAPBinding;
import javax.jws.soap.SOAPBinding.Style;
import javax.jws.soap.SOAPBinding.Use;

import com.google.common.base.Charsets;
import com.google.common.io.ByteSink;


import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.LogManager;



@WebService(serviceName = "LoginService", endpointInterface = "shipping.walmart.com.LoginService")
@SOAPBinding(style=Style.DOCUMENT, use=Use.ENCODED)


public class LoginServiceImpl implements LoginService {
	
	
	
    private static final Logger logger = LogManager.getLogger(LoginServiceImpl.class);

	public String getLoginidPassword(String loginid, String password)
    {
		
		
		logger.info("Get User : {}" );
        System.out.println(" user id" );

		
		try {
			 getEncryptedPassword(loginid, password ) ;
			
		}

		catch ( GeneralSecurityException  |  UnsupportedEncodingException e) {
			
			e.printStackTrace();
			
		}
    	    	 
        String authentication = "You are authorized";
        if(loginid.trim().toUpperCase().equals("User") && password.trim().toUpperCase().equals("WELCOME1"))
            authentication = (new StringBuilder(String.valueOf(loginid))).append(" you are an authorised user ").toString();
        else
        if(loginid.trim().toUpperCase().equals("Admin") && password.trim().toUpperCase().equals("WELCOME1"))
            authentication = (new StringBuilder(String.valueOf(loginid))).append(" you are an authorised user ").toString();
        else
        if(loginid.trim().toUpperCase().equals("Manager") && password.trim().toUpperCase().equals("WELCOME1"))
            authentication = (new StringBuilder(String.valueOf(loginid))).append(" you are an authorised user ").toString();
        else
            authentication = (new StringBuilder(String.valueOf(loginid))).append(" you are not an authorised user ").toString();

        return authentication;
        
    }

	
   private void getEncryptedPassword(String name, String data ) throws GeneralSecurityException , UnsupportedEncodingException {
	   CryptoUtils.removeCryptoRestriction() ;

	   logger.info("Get encrypted password : {}" );
       System.out.println(" user id" );

       
	   byte[] iv = CryptoUtils.generateIv();
	   byte[] key = CryptoUtils.generateKey();

	   byte[] encrypted = CryptoUtils.doCrypto(Cipher.ENCRYPT_MODE, key, iv, data.getBytes("UTF-8"));
	   System.out.println(new String(encrypted));
	   
	   try {
	        writeBinaryFile(encrypted, "KRISHNA",  "password.dat") ;
	 	   System.out.println(" Encrypted data has been written");
	        
	   }
	    catch (FileNotFoundException e) {
			e.printStackTrace();
		} 
	    catch (IOException e) {
			e.printStackTrace();
		}
	        
	        
	   
	   try {

		   encrypted = readPasswordFile("password.dat") ;
	 	   System.out.println(" Encrypted data has been read");

	   }
	    catch (FileNotFoundException e) {
			e.printStackTrace();
		} 
	    catch (IOException e) {
			e.printStackTrace();
		}
	   
	   
	   byte[] decrypted = CryptoUtils.doCrypto(Cipher.DECRYPT_MODE, key, iv, encrypted);
	   System.out.println(new String(decrypted));
	
    }
   private static void storeLoginData(String name, byte[] data) {
	   try {
			Properties properties = new Properties();
			properties.setProperty(name, data.toString());

			File file = new File("crypto.properties");
			FileOutputStream fileOut = new FileOutputStream(file);
			properties.store(fileOut, "Crypted Data");
			fileOut.close();
			
			   System.out.println ( " password file written" );
			
		} 
	    catch (FileNotFoundException e) {
			e.printStackTrace();
		} 
	    catch (IOException e) {
			e.printStackTrace();
		}
	   
   }
   private static String getLoginData(String name )  throws GeneralSecurityException , UnsupportedEncodingException {
	   
	   Properties prop = new Properties();
	   
	   byte[] decrypted = null;
	   
	   try {
	       prop.load(new FileInputStream("crypto.properties"));
	       
	       String password = prop.getProperty(name) ;
		   System.out.println(password);

		   byte[] iv = CryptoUtils.generateIv();
		   byte[] key = CryptoUtils.generateKey();

		   byte[] encrypted = password.getBytes() ;
		   
		   decrypted = CryptoUtils.doCrypto(Cipher.DECRYPT_MODE, key, iv, encrypted);
		   System.out.println(new String(decrypted));
		   
	       
	   } 
	   catch (IOException e)
	   {
		   
	   }
	   
		  return  decrypted.toString() ;
	   
	   
   }

   private static byte[] readPasswordFile(String passwordFileName)  throws IOException {
	   
	   Path path = Paths.get(passwordFileName);
	    return Files.readAllBytes(path);
	   
   }
 
   private static void writeBinaryFile(byte[] aBytes, String userID, String aFileName) throws IOException {
	    Path path = Paths.get(aFileName);
	    
	    Files.write(path, aBytes); //creates, overwrites
	  }
   
   
   
   public void writeByteFile() throws IOException 
   {
       String expectedValue = "Hello world";
   
       File file = new File("password.bin");
   
       ByteSink sink = com.google.common.io.Files.asByteSink(file);
       
       sink.write(expectedValue.getBytes());
      
  
        String result = com.google.common.io.Files.toString(file, Charsets.UTF_8);
   
   }
   
   public static  void main(String[] args) throws Exception
   {
	   
	   LoginServiceImpl log1 = new LoginServiceImpl() ;

   
	   
	   log1.getLoginidPassword("User", "WELCOME1") ;
   }

   
   
}