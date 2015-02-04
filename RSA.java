/*
 * Project 1: RSA Algorithm
 * 
 * Algorithms- Dr. Zhong-Hui Duan
 */

/**
 * @author : Adithya Addanki (aa207)
 */
 
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.Scanner;
import java.math.BigInteger;
import java.util.Random;

public class RSA {
	
	static final BigInteger zero=new BigInteger("0");
	static final BigInteger one=new BigInteger("1");
	static final BigInteger two=new BigInteger("2");
	static final BigInteger _128=new BigInteger("128");
	
	public static void main(String ar[]){
	BigInteger primeNum_p=new BigInteger("23");
	BigInteger primeNum_q=new BigInteger("29");

	try{
		
	//Safe Check for Improper Usage
	if(ar.length < 1)
	{
		System.out.println("Improper Usage of RSA");
		System.out.println("Enter \"java RSA Help\" regarding RSA Usage");
		return ;
	}
	//Help for displaying the usage terms
	else if(ar[0].equalsIgnoreCase("help"))
	{
		RSAHelp();
		return ;
	}
	//Generate a prime of N digits
	else if(ar.length==1)
	{
		BigInteger number1=generateRandNum(Integer.parseInt(ar[0]));
		if(number1.compareTo(one)>0)
			while(!primalityTest(number1))
			{
				number1=generateRandNum(Integer.parseInt(ar[0]));
			}
		primeNum_p=number1;
		
		System.out.println("Prime Number("+ar[0]+" digits)  \np: "+primeNum_p);
	}
	//gcd(a,b) = ax+by | y>0 , returns a pair (x,y)");
	else if(ar.length==2)
	{
		BigInteger num1=new BigInteger(ar[0]);
		BigInteger num2=new BigInteger(ar[1]);
		BigInteger temp=zero;
		BigInteger arr[]=new BigInteger[]{one,one,one};
		if(num1.compareTo(num2)>=0)
		{
			arr=calcGCD(num1,num2);
		}
		else
		{
			arr=calcGCD(num2,num1);
			temp=arr[1];
			arr[1]=arr[2];
			arr[2]=temp;
		}
		
		System.out.println("x : "+arr[1]);
		System.out.println("y : "+arr[2]);
	}
	//RSA e p q; e is the public key, p and q being the prime numbers
	else if(ar.length==3)
	{
		BigInteger e=new BigInteger(ar[0]);
		BigInteger p=new BigInteger(ar[1]);
		BigInteger q=new BigInteger(ar[2]);
		BigInteger[] d_n_BI=invModulo(e,p,q);
		System.out.println("d : "+d_n_BI[1]);
		System.out.println("n : "+d_n_BI[2]);
	}
	//RSA 'e' e n message; e-encrypts the 'message' with public key e
	//RSA 'd' d n message; d-decrypts the 'message' with private key d
	else if(ar.length==4)
	{
		//encryption case
		if(ar[0].equals("e"))
		{
			BigInteger e=new BigInteger(ar[1]);
			BigInteger n=new BigInteger(ar[2]);
			String eMessage=ar[3];
			String encryptedMessage[]=encRSA(e,n,eMessage);
			System.out.println("Encrypted Message: ");
			for(int i=0;i<encryptedMessage.length;i++)
			{
				if(encryptedMessage[i]!=null &&
							!encryptedMessage[i].equals(null))
					System.out.print(encryptedMessage[i]+" ");
			}
			System.out.println();
		}
		//decryption case
		else if(ar[0].equals("d"))
		{
			BigInteger d=new BigInteger(ar[1]);
			BigInteger n=new BigInteger(ar[2]);
			String dMessage=ar[3];
			String decryptedMessage[]=decRSA(d,n,dMessage);
			System.out.println("Decrypted Message: ");
			for(int i=0;i<decryptedMessage.length;i++)
			{
				System.out.print(decryptedMessage[i]);
			}
		}
	}
	}
	catch(Exception e){
		System.out.println("Encountered an isuue.");
		System.out.println(e.getMessage());
		RSAHelp();
	}
	}	

	//Function for Modular Exponentiation m^e mod N
	//Params: M is an integer to be raised to power e and then mod by N
	public static BigInteger modExp(BigInteger m,BigInteger e, BigInteger n){
		if(e.compareTo(zero)==0)
				return one;
		BigInteger spltVal=modExp(m, e.divide(two), n);
		if(isEven(e))
			return spltVal.multiply(spltVal).mod(n);
		else
			return ((spltVal.multiply(spltVal).mod(n))
										.multiply(m).mod(n)).mod(n);
	}

	//Function for RSA Encryption
	//Params e-public key,n=p*q and m is the message for encryption
	public static String[] encRSA(BigInteger e, BigInteger n, String m) 
	throws Exception{
		char x;	
		String msg=m;
		int noChars=m.length();
		BigInteger val=zero;
		int noSpltChars=1;
		int ic=0;
		
		//Check if the given N value is enough and if so for how many chars.
		for(ic=0;ic<noChars;ic++)
		{
			val=val.add(one.multiply(_128.pow(ic)));
			if(val.compareTo(n)>0)
				{
					noSpltChars=ic-1;
					break;
				}
		}
		if(ic==noChars)
			noSpltChars=noChars;
		//Splitting the Message into chunks of tiny alphanumeric strings
		String encMesg[]= new String[(int)(m.length()/noSpltChars)+1];
		int eMI=0;
		int ind=0;
		int ind2=0;
		
		while(ind2<noChars)
		{
			BigInteger wordVal=zero;
			BigInteger encWVal=zero;
			
			ind2=ind+noSpltChars;
			if(ind2>m.length())
				ind2=m.length();
			String wordExt=m.substring(ind,ind2);
			//System.out.println("Extracted Word: "+wordExt);
			for(int i1=wordExt.length()-1;i1>=0;i1--){
				x=wordExt.charAt(i1);
				BigInteger cVal=new BigInteger((int)x+"");
				wordVal=wordVal.add(cVal.multiply(_128.pow(i1)));
			}
			//Performing Modular Exponentiation
			encWVal=modExp(wordVal,e,n);
			//Storing in the String array
			encMesg[eMI++]=encWVal.toString();
			ind=ind2;
		}
		return encMesg;
	}

	//Function for RSA Decryption
	//Params d-private key,n=p*q and m is the message for decryption
	public static String[] decRSA(BigInteger d, BigInteger n, String m){
		char x;
		//Extraction based split on space character
		String arr[]=m.split(" ");
		String decMesg[]= new String[arr.length];
		for(int el=0;el<arr.length;el++){
			String wordVal="";
			BigInteger decWVal=zero;
			BigInteger decWValCopy=zero;
			String word=arr[el];
			decWVal=modExp(new BigInteger(word), d, n);
			decWValCopy=decWVal;
			// decoding to the string
			while(decWValCopy.compareTo(zero)!=0)
			{
				x=(char)decWValCopy.mod(_128).intValue();
				wordVal+=x;
				decWValCopy=decWValCopy.divide(_128);
			}
			decMesg[el]=wordVal;
		}
		//Message that is decrypted using private key d
		return decMesg;
	}

	// Defining Inverse Modulo function
	//Params: e being the public key finds a private key d with the help of p 
	//and q; our primes
	public static BigInteger[] invModulo(BigInteger e, BigInteger p, BigInteger q){
		BigInteger phyN=(p.subtract(BigInteger.ONE))
									.multiply(q.subtract(BigInteger.ONE));
		BigInteger[] privKey=new BigInteger[]{one,one,one};
		if(e.compareTo(phyN)>=0)
		{
			privKey=calcGCD(e,phyN);
		}
		else
		{
			privKey=calcGCD(phyN,e);
			privKey[1]=privKey[2];
			if(privKey[1].compareTo(zero)<0)
				privKey[1]=privKey[1].add(phyN);
		}
		privKey[2]=p.multiply(q);
		return privKey;
	}

	//Function for GCD calculation based on recursion
	//Params: Two integers n1 and n2
	public static BigInteger[] calcGCD(BigInteger n1, BigInteger n2){
		BigInteger[] bi=new BigInteger[]{n1,one,zero};
		BigInteger[] bitemp=new BigInteger[]{one,one,one};
		if(n2.compareTo(zero)==0)
			return bi;
		bitemp=calcGCD(n2, n1.mod(n2));
		bi[0]=bitemp[0];
		bi[1]=bitemp[2];
		bi[2]=bitemp[1].subtract((n1.divide(n2)).multiply(bitemp[2]));
		return bi;
	}

	//Function for getting base to check for primality of a number
	//Params: integer for which bases are returned randomly
	public static BigInteger getBase(BigInteger bi){
		int length=bi.toString().length();
		int rnd=5;
		Random r=new Random();
		if(length<=2)
			return new BigInteger(2+"");
		
		rnd=r.nextInt(99);
		while(rnd==1)
			rnd=r.nextInt(99);
			
		return new BigInteger(((rnd+1)+""));
	}

	// Function for primality check with three random different bases.
	//Params: integer 
	public static boolean primalityTest(BigInteger bi){
		BigInteger bi_min_1=bi.subtract(one);
		Random r=new Random();
		BigInteger a=getBase(bi);
		BigInteger a1=getBase(bi);
		BigInteger a2=getBase(bi);
		if(modulo(a,bi_min_1,bi).compareTo(one)==0){
			if(modulo(a1,bi_min_1,bi).compareTo(one)==0){
				if(modulo(a2,bi_min_1,bi).compareTo(one)==0){
					return true;
				}
				else
					return false;
			}
			else
				return false;
		}
		return false;
	}

	//Function for generating a random number of n digits
	public static BigInteger generateRandNum(int nofdig){
		BigInteger bigRand=zero;
		String temp="";
		Random r=new Random();
		for(int i=0;i<nofdig;i++){
			temp+=(r.nextInt(9)+1);
		}
		bigRand=new BigInteger(temp);
		if(bigRand.compareTo(one)==0)
			return bigRand.add(one);
		return bigRand;
	}

	// Modulo : Recursive Function for Modular Arithmetic
	// Params: integer a; the base and p-1 and p
	public static BigInteger modulo(BigInteger a,BigInteger p_min_1, BigInteger p){
		BigInteger rem=zero;
		BigInteger splt=one;
		
		//Base case
		if(p_min_1.compareTo(zero)==0)
			return splt;
		
		if(isEven(p_min_1)){
			BigInteger temp=modulo(a,p_min_1.divide(two),p);
			splt=(temp.multiply(temp)).mod(p);
		}
		else{
			BigInteger temp=modulo(a,p_min_1.divide(two),p);
			splt=(temp.multiply(temp)).mod(p);
			splt=(splt.multiply(a)).mod(p);
		}
		rem=splt;
		return rem;
	}

	//Multiplication: Rec function for Mul
	// Params: two integers
	public static BigInteger mulBi(BigInteger bi1, BigInteger bi2){
		BigInteger bi=zero;
		//Base Case
		if(bi2.compareTo(zero)==0)
			return bi;
		if(isEven(bi2)){
			bi=mulBi(bi1,bi2.divide(two));
			bi=bi.add(bi);
		}
		else{
			bi=mulBi(bi1,bi2.divide(two));
			bi=bi.add(bi);
			bi=bi.add(bi1);
		}
		return bi;
	}

	// Exponentiation: Function for Fast Exponentiation: a^p
	// Params: base and exponent
	public static BigInteger powerBi(BigInteger a,BigInteger p){
		BigInteger bi=one;
		// Base Case
		if(p.compareTo(zero)==0){
			return bi;
		}
		if(isEven(p))
		{
			BigInteger temp=powerBi(a,p.divide(two));
			bi=temp.multiply(temp);
		}
		else
		{
			BigInteger temp=powerBi(a,p.divide(two));
			bi=temp.multiply(temp);
			bi=bi.multiply(a);
		}
		return bi;
	}

	//GCD: Recursive function for Calculating GCD
	// Params: two Integers
	public static BigInteger biGCD(BigInteger bi1,BigInteger bi2){
		return biGCD(bi1.mod(bi2), bi2);	
	}

	// Function to check if number is even
	public static boolean isEven(BigInteger bi){
		BigInteger[] qr=bi.divideAndRemainder(two);
		if(qr[1].compareTo(zero)==0)
			return true;
		return false;
	}

	//Function for RSA Help; complements the readme.txt included with source code
	public static void RSAHelp(){
		System.out.println("*******************");
		System.out.println("*****RSA Help******");
		System.out.println("1. java RSA n; n: number of digits for prime generation");
		System.out.println("2. java RSA a b; gcd(a,b) = ax+by | y>0 , returns a pair (x,y)");
		System.out.println("3. java RSA e p q; e is the public key, p and q being the prime numbers");
		System.out.println("4. java RSA 'e' e n message; e-encrypts the 'message' with public key e");
		System.out.println("5. java RSA 'd' d n message; d-decrypts the 'message' with private key d");
		System.out.println("*******************");
	}
}

