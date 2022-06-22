import java.security.SecureRandom;
import java.util.*;
import java.io.*;
import java.math.*;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.InvalidKeyException;
import java.util.Scanner;
import java.nio.charset.*;
import org.apache.commons.io.*;
import org.apache.commons.lang3.ArrayUtils;
import java.awt.datatransfer.StringSelection;
import java.awt.Toolkit;
import java.awt.datatransfer.Clipboard;
import org.apache.commons.net.util.Base64;
import org.springframework.security.crypto.bcrypt.BCrypt;

public class RSAMario {

	//INITIAL FULL VALUES
	public static BigInteger eforrsa = BigInteger.valueOf(3);

	public static void main(String[] args) throws Exception {

	registerPage();

	while(!loginPage()){
		System.out.println("Wrong password! Try again!\n");
	}

	System.out.println("Decrypting your file...");
	decryptFILE();
	int option=0;

	while (option != 6) {
		option = menu();
		switch (option) {
			case 1:
				savePassword();
				break;
			case 2:
				searchPassword();
				break;
			case 3:
				updatePassword();
				break;
			case 4:
				deletePassword();
				break;
			case 5:
				randomPass();
				break;
			case 6:
				System.out.println("Exiting, file encrypted.");
				encryptFILE();
				System.exit(0);
				break;
			default:
		}
	}

	encryptFILE();

	}

	public static int menu(){

		Scanner sc = new Scanner(System.in);

		System.out.println("Password Manager Application\n");
		System.out.println("1. Save new password\n");
		System.out.println("2. Search password by title\n");
		System.out.println("3. Update password by title\n");
		System.out.println("4. Delete password\n");
		System.out.println("5. Random password generator\n");
		System.out.println("6. Exit\n");

		System.out.println("Choose what you want to do: \n");

		int result = sc.nextInt();

		return result;

	}

	public static void savePassword() throws IOException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {

		Scanner savesc = new Scanner(System.in);
		StringBuilder sb = new StringBuilder();

		System.out.println("Write the title:\n");
		String title = savesc.nextLine();

		System.out.println("Write your password\n");
		String password = savesc.nextLine();

		System.out.println("Write your URL\n");
		String url = savesc.nextLine();

		System.out.println("Which password encryption system do you want to use\n");
		System.out.println("AES (1), DES (2), RSA (3)\n");
		int selection = savesc.nextInt();

		String encryptedpass = "test";
		String usedalg = "";

		switch (selection){

			case 1:
				encryptedpass=AESencryption(password);
				usedalg = "1";
				break;

			case 2:
				encryptedpass=DESencryption(password);
				usedalg = "2";
				break;

			case 3:
				encryptedpass=RSAencryption(password);
				usedalg = "3";
				break;
		}

		sb.append(title);
		sb.append(" ");
		sb.append(encryptedpass);
		sb.append(" ");
		sb.append(usedalg);
		sb.append(" ");
		sb.append(url);
		sb.append("\n");

		FileWriter fr = new FileWriter("database.txt",true);
		BufferedWriter br = new BufferedWriter(fr);

		br.append(sb.toString());
		br.close();

	}

	public static void searchPassword() throws IOException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, ClassNotFoundException {

		Scanner searchsc = new Scanner(System.in);

		System.out.println("Insert title:\n");
		String title = searchsc.nextLine();
		char[] titlearray = new char[title.length()];
		for (int i = 0;i < title.length(); i++){
			titlearray[i] = title.charAt(i);
		}

		String file = readFile().toString();
		char[] filearray = new char[file.length()];
		for (int i = 0;i < file.length(); i++){
			filearray[i] = file.charAt(i);
		}

		String splitfile[] = file.split("[\\s\\n]");

		/*
		for (String a : splitfile){
			System.out.println(a);
		}

		 */

		String password ="";
		String type ="";

		for (int i = 0; i < splitfile.length; i++){
			if(splitfile[i].equals(title)){
				password=splitfile[i+1];
				type=splitfile[i+2];
			}
		}

		String decryptedpass = "";

		if(type.equals("1")){
			decryptedpass=AESdecryption(password);
		} else if (type.equals("2")){
			decryptedpass=DESdecryption(password);
		} else {
			decryptedpass=RSAdecryption(password);
		}

		System.out.println("Password has been found!\n");
		System.out.println(password);
		System.out.println("Do you want to see decrypted password?(y/n)\n");
		Scanner passsc = new Scanner(System.in);
		Scanner clipboardsc = new Scanner(System.in);
		char yes = passsc.nextLine().charAt(0);
		if(yes == 'y') {
			System.out.println("Your password is: ");
			//System.out.println(RSAdecryption(password));
			System.out.println(decryptedpass);

			System.out.println("Do you want to copy it to clipboard?(y/n)\n");
			char clip = clipboardsc.nextLine().charAt(0);
			if (clip == 'y'){
				StringSelection stringSelection = new StringSelection(decryptedpass);
				Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
				clipboard.setContents(stringSelection, null);
				System.out.println("Text successfully copied to clipboard!\n");
			}
		}

	}

	public static void updatePassword() throws IOException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {

		Scanner searchsc = new Scanner(System.in);

		System.out.println("Insert title:\n");
		String title = searchsc.nextLine();
		char[] titlearray = new char[title.length()];
		for (int i = 0;i < title.length(); i++){
			titlearray[i] = title.charAt(i);
		}

		String file = readFile().toString();
		char[] filearray = new char[file.length()];
		for (int i = 0;i < file.length(); i++){
			filearray[i] = file.charAt(i);
		}

		String splitfile[] = file.split("[\\s\\n]");

		/*
		for (String a : splitfile){
			System.out.println(a);
		}

		 */

		String password ="";
		String type ="";


		for (int i = 0; i < splitfile.length; i++){
			if(splitfile[i].equals(title)){
				//password=splitfile[i+1];
				type=splitfile[i+2];
			}
		}

		Scanner newpasssc = new Scanner(System.in);
		System.out.println("Insert your new password for this title: \n");
		String newpassword = "";
		String inputpass = newpasssc.nextLine();
		int typeint = Integer.valueOf(type);

		switch (typeint){

			case 1:
				newpassword=AESencryption(inputpass);
				break;

			case 2:
				newpassword=DESencryption(inputpass);
				break;

			case 3:
				newpassword=RSAencryption(inputpass);
				break;
		}

		for (int i = 0; i < splitfile.length; i++){
			if(splitfile[i].equals(title)){
				splitfile[i+1]=newpassword;
			}
		}

		/*
		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < splitfile.length; i=+4){
			sb.append(splitfile[i]);
			sb.append(" ");
			sb.append(splitfile[i+1]);
			sb.append(" ");
			sb.append(splitfile[i+2]);
			sb.append(" ");
			sb.append(splitfile[i+3]);
			sb.append("\n");
		}

		System.out.println(sb.toString());

		 */

		FileWriter fr = new FileWriter("database.txt");
		BufferedWriter br = new BufferedWriter(fr);
		int aux = 1;
		for (int i = 0; i < splitfile.length; i++) {

			br.append(splitfile[i]);
			br.append(" ");

			if (aux == 4 || aux == 8 || aux == 12 || aux == 16 || aux == 20 || aux == 24){
				br.append("\n");
			}
			aux++;
		}
		br.close();
	}

	public static void deletePassword() throws IOException {

		Scanner searchsc = new Scanner(System.in);

		System.out.println("Insert title:\n");
		String title = searchsc.nextLine();
		char[] titlearray = new char[title.length()];
		for (int i = 0;i < title.length(); i++){
			titlearray[i] = title.charAt(i);
		}

		String file = readFile().toString();
		char[] filearray = new char[file.length()];
		for (int i = 0;i < file.length(); i++){
			filearray[i] = file.charAt(i);
		}

		String splitfile[] = file.split("[\\s\\n]");

		System.out.println("SPLITFILE 1");
		for (String a : splitfile){
			System.out.println(a);
		}

		String rtitle = "";
		String rpass = "";
		String rnum = "";
		String rurl = "";
		int index1,index2,index3,index4;

		for (int i = 0; i < splitfile.length; i++){
			if(splitfile[i].equals(title)){
				rtitle = splitfile[i];
				rpass = splitfile[++i];
				rnum = splitfile[++i];
				rurl = splitfile[++i];
			}
		}

		System.out.println(rtitle);
		System.out.println(rpass);
		System.out.println(rnum);
		System.out.println(rurl);

		String []splitfile1 = ArrayUtils.removeElement(splitfile, rtitle);
		String []splitfile2 = ArrayUtils.removeElement(splitfile1, rpass);
		String []splitfile3 = ArrayUtils.removeElement(splitfile2, rnum);
		String []splitfile4 = ArrayUtils.removeElement(splitfile3, rurl);

		System.out.println("SPLITFILE 4");
		for (String a : splitfile4){
			System.out.println(a);
		}

		FileWriter fr = new FileWriter("database.txt");
		BufferedWriter br = new BufferedWriter(fr);

		for (int i = 0; i < splitfile4.length; i++) {

			if (i == 3 || i == 7 || i == 11 || i == 15 || i == 19 || i == 23){
				br.append(splitfile4[i]);
				br.append("\n");
			} else {
				br.append(splitfile4[i]);
				br.append(" ");
			}

		}
		//br.append("\n");
		br.close();


	}

	public static void encryptFILE() throws Exception {

		String aux = readFile().toString();
		String encryptedfile = AESencryption(aux);

		FileWriter fr = new FileWriter("database.txt");
		BufferedWriter br = new BufferedWriter(fr);

		br.append(encryptedfile);
		br.close();

	}

	public static void decryptFILE() throws IOException {

		String aux = readFile().toString();
		String encryptedfile = AESdecryption(aux);

		FileWriter fr = new FileWriter("database.txt");
		BufferedWriter br = new BufferedWriter(fr);

		br.append(encryptedfile);
		br.close();


	}

	public static String AESencryption(String pass){
		Random rand = new Random();
		EncryptionDecryptionUtil aesaux = new EncryptionDecryptionUtil();
		String result=aesaux.encrypt("password",pass);

		return result;
	}

	public static String AESdecryption(String pass){
		Random rand = new Random();
		EncryptionDecryptionUtil aesaux = new EncryptionDecryptionUtil();
		String result=aesaux.decrypt("password",pass);

		return result;
	}

	public static String DESencryption(String pass) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOException {

		KeyGenerator keyGen = KeyGenerator.getInstance("DES");
		//keyGen.init(256);
		SecretKey key = keyGen.generateKey();
		byte[] encoded = key.getEncoded();

		try (FileOutputStream fos = new FileOutputStream("keysaving.txt")){
			fos.write(encoded);
		}

		Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");

		cipher.init(Cipher.ENCRYPT_MODE,key);
		/*
		byte[] message = pass.getBytes();
		byte[] messageEnc = cipher.doFinal(message);

		 */

		byte[] messageEnc = Base64.encodeBase64(
				cipher.doFinal(pass.getBytes("UTF-8")));


		String result = new String(messageEnc);

		return result;
	}

	public static String DESdecryption(String pass) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOException, ClassNotFoundException {


		byte[] decoded;
		try (FileInputStream fis = new FileInputStream("keysaving.txt")){
			decoded = fis.readAllBytes();
		}

		System.out.println("PASS FOR DES DECRPYTION IS:\n");
		System.out.println(pass);

		SecretKey secretKey = new SecretKeySpec(decoded, "DES");

		Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");

		cipher.init(Cipher.DECRYPT_MODE,secretKey);
		/*
		byte[] message = pass.getBytes();
		byte[] messageEnc = cipher.doFinal(message);

		 */
		byte[] message = Base64.decodeBase64(pass.getBytes());
		byte[] messageEnc = cipher.doFinal(message);

		String result = new String(messageEnc);

		return result;

	}

	public static String RSAencryption(String pass){

		BigInteger p = BigInteger.valueOf(3);
		int paux = p.intValue();

		BigInteger q = BigInteger.valueOf(11);
		int qaux = q.intValue();

		BigInteger n = p.multiply(q);
		BigInteger phi = p.subtract(new BigInteger("1")).multiply(q.subtract(new BigInteger("1")));
		int onn = ((paux - 1) * (qaux - 1));
		BigInteger on = BigInteger.valueOf(onn);

		//BigInteger e = new BigInteger(10, new Random());
		BigInteger e = eforrsa;
		/*
		while (true) {
			if (e.gcd(phi).equals(new BigInteger("1")) && e.compareTo(on) <= 0) {
				break;
			} else {
				e = new BigInteger(10, new Random());
			}
		}

		 */

		BigInteger d = e.modInverse(phi);

		String str = pass;
		int[] str1 = new int[str.length()];
		char aux;
		for (int i = 0; i < str.length(); i++) {
			aux = str.charAt(i);
			str1[i] = (int)aux;
		}

		int[] result = new int[str.length()];
		int i = 0;
		for (int a : str1) {
			BigInteger m = BigInteger.valueOf(a);

			BigInteger auxi = m.modPow(e, n);
			result[i]=auxi.intValue();
			i++;
		}

		StringBuilder sbuild = new StringBuilder();
		String fullresult = "test";
			for (int a : result){
				String avalue = Integer.toString(a);
				sbuild.append(avalue);
				sbuild.append(".");
			}

			return sbuild.toString();
	}

	public static String RSAdecryption(String pass){

		String decrypted[] = pass.split("[.]");
		String result[] = new String [decrypted.length];

		int nn = 33;
		int pp = 3;
		int qq = 11;
		BigInteger p = BigInteger.valueOf(pp);
		BigInteger q = BigInteger.valueOf(qq);

		BigInteger phi = p.subtract(new BigInteger("1")).multiply(q.subtract(new BigInteger("1")));

		BigInteger e = eforrsa;
		BigInteger ddd = e.modInverse(phi);
		Integer dd = ddd.intValue();
		String d = dd.toString();
		String n = Integer.toString(nn);
		/*
		System.out.println("Decrypted result: ");

		for (String a : decrypted){
			BigInteger M = new BigInteger(a).modPow(new BigInteger(d), new BigInteger(n));
			System.out.println(M.toString());

		}

		 */

		for (int i = 0; i < decrypted.length; i++){
			BigInteger M = new BigInteger(decrypted[i]).modPow(new BigInteger(d), new BigInteger(n));
			int mint = M.intValue();
			String mstring = Integer.toString(mint);
			result[i] = mstring;
		}

		String delimiter = "";
		String finalresult = String.join(delimiter, result);
		return finalresult;
	}

	public static String readFile() throws IOException{
		File file = new File("database.txt");
		return FileUtils.readFileToString(file, String.valueOf(StandardCharsets.UTF_8));
	}

	public static void registerPage() throws IOException {
		Scanner regscan = new Scanner(System.in);
		Scanner regscan2 = new Scanner(System.in);

		System.out.println("Welcome:\n");
		System.out.println("Do you want to Register or Login?(r/l)\n");
		char input = regscan.nextLine().charAt(0);
		if (input == 'r'){
			System.out.println("REGISTER PAGE:\n");
			System.out.println("Please write your password for the system:\n");
			String password = regscan2.nextLine();
			String pw_hash = BCrypt.hashpw(password, BCrypt.gensalt());
			File file = new File("users.txt");
			FileWriter fr = new FileWriter(file);
			BufferedWriter br = new BufferedWriter(fr);

			br.append(pw_hash);
			br.close();
		}

	}

	public static boolean loginPage() throws IOException {
		File userfile = new File("users.txt");
		String hashpass = FileUtils.readFileToString(userfile, String.valueOf(StandardCharsets.UTF_8)).toString();

		Scanner logsc = new Scanner(System.in);
		System.out.println("LOGIN PAGE\n");
		System.out.println("Please write your password to log into the system:\n");
		String password = logsc.nextLine();

		if(BCrypt.checkpw(password, hashpass)){
			return true;
		} else {
			return false;
		}

	}

	public static void randomPass(){
		Scanner randomsc = new Scanner(System.in);
		Scanner randomsc2 = new Scanner(System.in);
		System.out.println("Do you want to generate a random password?(y/n)\n");
		char input = randomsc.nextLine().charAt(0);
		if(input == 'y'){
			System.out.println("Your randomly generated password is:\n");
			String randompassword = generateRandomPassword(10);
			System.out.println(randompassword);

			System.out.println("Do you want to copy it to clipboard?(y/n)\n");
			char input2 = randomsc2.nextLine().charAt(0);
			if(input2 == 'y'){
				StringSelection stringSelection = new StringSelection(randompassword);
				Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
				clipboard.setContents(stringSelection, null);
				System.out.println("Text successfully copied to clipboard!\n");
			}
		}
	}

	public static String generateRandomPassword(int len)
	{
		final String chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

		SecureRandom random = new SecureRandom();
		StringBuilder sb = new StringBuilder();

		for (int i = 0; i < len; i++)
		{
			int randomIndex = random.nextInt(chars.length());
			sb.append(chars.charAt(randomIndex));
		}

		return sb.toString();
	}

}
