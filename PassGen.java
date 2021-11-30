package StrongPassword;
import java.io.*;
import java.net.*;
import java.util.*;
public class PassGen {
	//Scanner sc = new Scanner(System.in);

	public static void main(String[] args) {
		Scanner sc = new Scanner(System.in);
		System.out.println("Please enter the length of the Key required: ");
		/* Here the Length of the key to be generated is a minimum of 4
		 * characters, and the length is to be taken from web page
		 * (front end) using range bar or length input in the front end
		 */
		try {
		new PassGen().client();
		}catch(Exception exx) {}
		int n = sc.nextInt();
		System.out.println(generatePassword(n));

	}
	
	void client()throws Exception
	{
		Socket s=new Socket("192.168.137.1",9999);
		DataInputStream dis=new DataInputStream(s.getInputStream());
		DataOutputStream dout=new DataOutputStream(s.getOutputStream());
		String str=dis.readUTF();
		System.out.println(str);
	}
	 private static char[] generatePassword(int length) {
	      String capitalCaseLetters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
	      String lowerCaseLetters = "abcdefghijklmnopqrstuvwxyz";
	      String specialCharacters = "!@#$%^&*";
	      String numbers = "1234567890";
	      String combinedChars = capitalCaseLetters + lowerCaseLetters + specialCharacters + numbers;
	      Random random = new Random();
	      char[] password = new char[length];

	      password[0] = lowerCaseLetters.charAt(random.nextInt(lowerCaseLetters.length()));
	      password[1] = capitalCaseLetters.charAt(random.nextInt(capitalCaseLetters.length()));
	      password[2] = specialCharacters.charAt(random.nextInt(specialCharacters.length()));
	      password[3] = numbers.charAt(random.nextInt(numbers.length()));
	   
	      for(int i = 4; i< length ; i++) {
	         password[i] = combinedChars.charAt(random.nextInt(combinedChars.length()));
	      }
	      return password;
 }
	

}
