/*--------------------------------------------------------

William Chirciu  2/17/2018:

Official Header from CSC 435 Website

Command-line compilation instructions:


> javac Blockchain.java


Instructions to run this program:
using a script

> start java Blockchain 0
> start java Blockchain 1
> start java Blockchain 2


List of files needed for submission

a. checklist-block.html
b. Blockchain.java
c. BlockchainLog.txt
d. BlockchainLedgerSample.xml
e. BlockInput0.txt, BlockInput1.txt, BlockInput2.txt

Notes:

If by rare chance the program decides to create too many blocks or too few, just restart the application. This is a threading issue. 
I tried to minimize the chance of this happening by manipulating Sleeps. The way I have it now appears to be optimal so everything 
should run correctly.

Type in console commands EXACTLY as you see them listed, otherwise nothing will happen (case-sensitive)

When reading in a new file, follow procedure:

R filename.txt     // be sure to include the extension

Credits:

The skeleton of the following classes were retrieved from bc.java on Clark Elliott's webpage:
BlockchainServer.class
BlockchainWorker.class
Ports.class
PublicKeyServer.class
PublicKeyWorker.class
UnverifiedBlockConsumer.class
UnverifiedBlockServer.class
UnverifiedBlockWorker.class
main (initialization of threads)

XML Marshalling and Signature techniques were received from BlockH.java on Clark Elliott's webpage

The process for creating a SHA256 hash string and performing "work" was taken from WorkA.java on Clark Elliott's webpage
----------------------------------------------------------*/

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.io.StringReader;
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Comparator;
import java.util.Date;
import java.util.HashMap;
import java.util.Scanner;
import java.util.UUID;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.PriorityBlockingQueue;

import javax.xml.bind.DatatypeConverter;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.PropertyException;
import javax.xml.bind.Unmarshaller;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;


// All of the information held in a single block of the block chain
@XmlRootElement(name = "BlockRecord")
class BlockRecord{

	@XmlElement(name = "BlockID", required = true)
	private String blockUUIN; //The universal identification number of this block record
	private String signedUUIN; //The signed UUINN of this block
	private String blockNum;  //The Block number represents this block's position in the blockchain
	private String timeStamp; //Time when this block was created
	private String creatingProcess; //id of the process that created this block
	private String verificationProcessId; //Contains the id of the process that verified this block
	private String randomString; //String used to concatenate with prevHash and data input
	private String SHA256;  //hash of this block
	private String signedSHA256; //signed hash of this block
	
	//---------------------- Data From File ----------------------------------------//
	private String FName;
	private String LName;
	private String DoB;
	private String SSN;
	private String Diagnosis;
	private String Treatment;
	private String Medicine;

	//returns concatenated data for hashing purposes.
	public String getConcatData() {
		return blockUUIN + " " + FName + " " + LName + " " + DoB + " " + SSN + " " + Diagnosis + 
				" " + Treatment + " " + Medicine;
	}

	//-------------------------------- Getters and Setters -----------------------------------------//
	public String getblockUUIN() {
		return blockUUIN;
	}
	public String getSignedUUIN() {
		return signedUUIN;
	}

	public void setSignedUUIN(String signedUUIN) {
		this.signedUUIN = signedUUIN;
	}

	public String getBlockNum() {
		return blockNum;
	}

	public void setBlockNum(String blockNum) {
		this.blockNum = blockNum;
	}

	public void setUUID(String blockUUIN) {
		this.blockUUIN = blockUUIN;
	}
	public String getTimeStamp() {
		return timeStamp;
	}
	public void setTimeStamp(String timeStamp) {
		this.timeStamp = timeStamp;
	}
	public String getCreatingProcess() {
		return creatingProcess;
	}
	public void setCreatingProcess(String creatingProcess) {
		this.creatingProcess = creatingProcess;
	}
	public String getVerificationProcessId() {
		return verificationProcessId;
	}
	public void setVerificationProcessId(String verificationProcessId) {
		this.verificationProcessId = verificationProcessId;
	}
	public String getRandomString() {
		return randomString;
	}
	public void setRandomString(String randomString) {
		this.randomString = randomString;
	}
	public String getSHA256() {
		return SHA256;
	}
	public void setSHA256(String sHA256) {
		SHA256 = sHA256;
	}
	public String getSignedSHA256() {
		return signedSHA256;
	}

	public void setSignedSHA256(String signedSHA256) {
		this.signedSHA256 = signedSHA256;
	}

	public String getFName() {
		return FName;
	}
	public void setFName(String fName) {
		FName = fName;
	}
	public String getLName() {
		return LName;
	}
	public void setLName(String lName) {
		LName = lName;
	}
	public String getDoB() {
		return DoB;
	}
	public void setDoB(String doB) {
		DoB = doB;
	}
	public String getSSN() {
		return SSN;
	}
	public void setSSN(String sSN) {
		SSN = sSN;
	}
	public String getDiagnosis() {
		return Diagnosis;
	}
	public void setDiagnosis(String diagnosis) {
		Diagnosis = diagnosis;
	}
	public String getTreatment() {
		return Treatment;
	}
	public void setTreatment(String treatment) {
		Treatment = treatment;
	}
	public String getMedicine() {
		return Medicine;
	}
	public void setMedicine(String medicine) {
		Medicine = medicine;
	}
}

// Ports class is responsible for setting the ports for public keys, 
//  unverified blocks, and updated block-chains for each process
class Ports{
	public static int publicKeyPort;
	public static int  unverifiedBlocksPort;
	public static int updatedBlockChainPort;


	public void setPorts(){
		publicKeyPort = 4710 + Blockchain.PID;
		unverifiedBlocksPort = 4820 + Blockchain.PID;
		updatedBlockChainPort = 4930 + Blockchain.PID;
	}
}

//Comparator for sorting priority queue based on the time stamps of the records
class TimeStampComparator implements Comparator<BlockRecord>
{
	@Override
	public int compare(BlockRecord t1, BlockRecord t2)
	{
		try {
			SimpleDateFormat sdf = new SimpleDateFormat("HH.mm.ss");
			Date d1 = sdf.parse(t1.getTimeStamp());
			Date d2 = sdf.parse(t2.getTimeStamp());
			if (d1.compareTo(d2) < 0)
			{
				return -1;
			}
			if (d1.compareTo(d2) > 0)
			{
				return 1;
			}
		} catch (ParseException e) {
			e.printStackTrace();
		}
		return 0;
	}
}

//Worker thread that handles incoming public keys
class PublicKeyWorker extends Thread { // Class definition
	Socket sock; // socket to receive public keys
	PublicKeyWorker (Socket s) {sock = s;} // C'tor
	public void run(){
		try{
			BufferedReader in = new BufferedReader(new InputStreamReader(sock.getInputStream()));
			String[] data = in.readLine().split(" "); //input comes in as "PublicKeyString ProcessID"
			String encodedKey = data[0];
			int processID = Integer.parseInt(data[1]);
			PublicKey pKey = getPublicKey(encodedKey); //decode public key string
			Blockchain.getInstance().addKeys(pKey, processID); //store received public key into hashmap
			if(processID != Blockchain.PID) {
				System.out.println("Received Public Key from Process " + processID);
			}
			sock.close(); 
		} catch (IOException x){x.printStackTrace();}
	}

	//Converts XML String sent through socket to Public Key of associated process
	public PublicKey getPublicKey(String keyString) {
		try {
			byte[] publicBytes = Base64.getDecoder().decode(keyString);

			//generate public key from decoded keyString
			X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicBytes);
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			PublicKey pubKey = keyFactory.generatePublic(keySpec);
			return pubKey;
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			e.printStackTrace();
		}
		return null;
	}
}

//Server which listens for multi-casted public keys
class PublicKeyServer implements Runnable {

	public void run(){
		int q_len = 6;
		Socket sock;
		System.out.println("Starting the Public Key Server input thread using " +
				Integer.toString(Ports.publicKeyPort));
		try{
			ServerSocket servsock = new ServerSocket(Ports.publicKeyPort, q_len);
			while (true) {
				sock = servsock.accept(); 				//received a public key
				new PublicKeyWorker (sock).start();		//create a worker thread to handle it 
			}
		}catch (IOException ioe) {System.out.println(ioe);}
	}
}

//Server which listens for multi-casted unverified blocks
class UnverifiedBlockServer implements Runnable {
	BlockingQueue<BlockRecord> queue;
	UnverifiedBlockServer(BlockingQueue<BlockRecord> queue){
		this.queue = queue; // Constructor binds our prioirty queue to the local variable.
	}

	//Worker responsible for unmarshalling unverified blocks and inserting
	// them into the priority queue
	class UnverifiedBlockWorker extends Thread { // Class definition
		Socket sock; // socket to receive unverified blocks
		UnverifiedBlockWorker (Socket s) {sock = s;} // C'tor
		public void run(){

			try {
				BufferedReader in = new BufferedReader(new InputStreamReader(sock.getInputStream()));
				StringBuilder sb = new StringBuilder();
				String line;

				while ((line = in.readLine()) != null) {
					sb.append(line);
				}
				String blockXML = sb.toString();
				BlockRecord block = getUnverifiedBlock(blockXML); //unmarshall block xml string
				System.out.println("Unverified block received from Process " + block.getCreatingProcess());
				queue.put(block); // insert block into priority queue
				sock.close();
			} catch (IOException e) {
				e.printStackTrace();
			} catch (InterruptedException e) {
				e.printStackTrace();
			} 

		}
	}

	//Unmarshalls Block Record from xml string
	public BlockRecord getUnverifiedBlock(String blockXML) {
		try {
			JAXBContext jaxbContext = JAXBContext.newInstance(BlockRecord.class);
			Unmarshaller jaxbUnmarshaller = jaxbContext.createUnmarshaller();
			StringReader reader = new StringReader(blockXML);

			BlockRecord unverifiedBlock = (BlockRecord) jaxbUnmarshaller.unmarshal(reader);
			return unverifiedBlock;
		} catch (JAXBException e) {
			e.printStackTrace();
		}
		return null;
	}

	public void run(){
		int q_len = 6;
		Socket sock;
		System.out.println("Starting the Unverified Block Server input thread using " +
				Integer.toString(Ports.unverifiedBlocksPort));
		try{
			ServerSocket servsock = new ServerSocket(Ports.unverifiedBlocksPort, q_len);
			while (true) {
				sock = servsock.accept(); // Received unverified block
				new UnverifiedBlockWorker(sock).start(); // create worker thread to handle block
			}
		}catch (IOException ioe) {System.out.println(ioe);}
	}
}

//Worker that handles multi-casted blockchains
class BlockchainWorker extends Thread { // Class definition
	Socket sock; // socket which receives the updated blockchain
	BlockchainWorker (Socket s) {sock = s;} // C'tor
	public void run(){
		try {
			BufferedReader in = new BufferedReader(new InputStreamReader(sock.getInputStream()));
			StringBuilder sb = new StringBuilder();
			String line;

			//build string from blockchain xml
			while ((line = in.readLine()) != null) {
				sb.append(line);
				sb.append("\n");
			}

			String blockChainXML = sb.toString();
			Ledger blockChainReceived = getUpdatedBlockchain(blockChainXML); //unmarshall blockchain xml
			if(!String.valueOf(Blockchain.PID).equals
					(blockChainReceived.BlockChain.get(blockChainReceived.getSize() -1).getVerificationProcessId())) {
				System.out.println("Received a new Blockchain from Process " + 
					blockChainReceived.BlockChain.get(blockChainReceived.getSize() - 1).getVerificationProcessId());
			}
			Ledger.updateBlockChain(blockChainReceived.BlockChain); //update this process's blockchain to the received one
			if(Blockchain.PID == 0) {
				Blockchain.buildXML();   //Process zero continually builds the "BlockchainLedger.xml" document
			}
			sock.close();
		} catch (IOException e) {
			e.printStackTrace();
		} 
	}
	//Unmarshalls Blockchain from xml string
	public Ledger getUpdatedBlockchain(String blockChainXML) {
		try {
			JAXBContext jaxbContext = JAXBContext.newInstance(Ledger.class);
			Unmarshaller jaxbUnmarshaller = jaxbContext.createUnmarshaller();
			StringReader reader = new StringReader(blockChainXML);

			Ledger blockChain = (Ledger) jaxbUnmarshaller.unmarshal(reader);
			return blockChain;
		} catch (JAXBException e) {
			e.printStackTrace();
		}
		return null;
	}
}

//Server listens for multi-casted blockchains
class BlockchainServer implements Runnable {
	public void run(){
		int q_len = 6; /* Number of requests for OpSys to queue */
		Socket sock;
		System.out.println("Starting the blockchain server input thread using " + Integer.toString(Ports.updatedBlockChainPort));
		try{
			ServerSocket servsock = new ServerSocket(Ports.updatedBlockChainPort, q_len);
			while (true) {
				sock = servsock.accept(); //received an updated blockchain
				new BlockchainWorker (sock).start();   //start a worker thread to handle the updated blockchain
			}
		}catch (IOException ioe) {System.out.println(ioe);}
	}
}

//Retrieves unverified blocks from priority queue and begins to verify them
class UnverifiedBlockConsumer implements Runnable {
	BlockingQueue<BlockRecord> queue;
	UnverifiedBlockConsumer(BlockingQueue<BlockRecord> queue){
		this.queue = queue; // Constructor binds our prioirty queue to the local variable.
	}

	public void run(){

		BlockRecord block;

		System.out.println("Starting the Unverified Block Priority Queue Consumer thread.\n");
		try{
			while(true){ // retrieve block from queue, perform work to verify, multicast the new blockchain if able

				block = queue.take(); //retrive unverified block from priority queue

				//Check to see if unverified block has already been verified (in blockchain), if so, discard
				if(Ledger.blockChainContainsBlock(block)) {
					continue;
				}

				//Verify that this block's UUIN was signed by its creator process. If not, discard
				Signature sig = Signature.getInstance("SHA1WithRSA");
				sig.initVerify(Blockchain.publicKeys.get(Integer.parseInt(block.getCreatingProcess())));
				sig.update(block.getblockUUIN().getBytes());
				if(!sig.verify(Base64.getDecoder().decode(block.getSignedUUIN()))){
					System.out.println("BLock ID verification failed");
					continue;
				}

				int workNumber = 0;				//Number we will try to guess from substring of generated hash value
				int size = Ledger.getSize();    //Current size of this process's block chain

				try {
					String hash = "";
					while(true){

						//If this block has been verified, discard
						if(Ledger.blockChainContainsBlock(block)) {
							break;
						}
						String randomString = Blockchain.randomAlphaNumeric(8); //Random alpha-numeric string of length 8
						block.setRandomString(randomString);					//insert random string into block record

						//SHA256 hash generated from concatenated data, the previous SHA56 hash in the
						//block chain, and the random string
						hash = Blockchain.generateHash(block.getConcatData(),Ledger.getPrevBlockHash(),randomString);

						block.setSHA256(hash);   //Insert SHA256 hash into Block Record

						// Create number from substring of hash Between 0000 (0) and FFFF (65535)
						workNumber = Integer.parseInt(hash.substring(0,4),16); 

						//check to see if workNumber is less than 20,000. If we lower the number, more work is required.
						if (workNumber < 20000){

							//if this block has already been verified, we end up discarding it, even though we solved the puzzle
							if(!Ledger.blockChainContainsBlock(block)) {
								try {
									//sign the SHA256 hash value with the verifying process's private key
									byte[] SHA256 = block.getSHA256().getBytes();
									sig.initSign(Blockchain.getInstance().getPrivateKey());
									sig.update(SHA256);
									byte[] signatureBytes = sig.sign();
									//insert signed SHA256 hash into block record
									block.setSignedSHA256((Base64.getEncoder().encodeToString(signatureBytes)));
								} catch (InvalidKeyException e) {
									e.printStackTrace();
								} catch (SignatureException e) {
									e.printStackTrace();
								}
								//insert verification process ID into block record
								block.setVerificationProcessId(String.valueOf(Blockchain.PID));

								//If the blockchain has been updated, we update the size variable and reset this 
								// block to unverified
								if(Ledger.getSize() > size) {
									size = Ledger.getSize();
									continue;
								}
								System.out.println("Work Puzzle Solved");
								System.out.println("Hash: " + hash);
								System.out.println("workNumber " + workNumber + " is less than 20,000");
								Ledger.addToBlockChain(block); //Add this block to this process's blockchain
								break;
							}
						}
						Thread.sleep(1000);
					}
				}catch(Exception ex) {ex.printStackTrace();}

				Thread.sleep(1500); // For the example, wait for our blockchain to be updated before processing a new block
			}
		}catch (Exception e) {System.out.println(e);}
	}
}

//Ledger wrapper class that holds the Blockchain
@XmlAccessorType(XmlAccessType.FIELD)
@XmlRootElement(name = "Ledger")
class Ledger{
	@XmlElement(name = "BlockRecord")
	static ArrayList<BlockRecord> BlockChain;	//our Blockchain

	Ledger(){} //C'tor

	//C'tor with a ledger as a parameter
	Ledger(ArrayList<BlockRecord> ledger){
		BlockChain = ledger;
	}

	//Initializes the blockchain for this process
	public static void initializeBlockChain() {
		BlockChain = new ArrayList<BlockRecord>();
	}

	//returns the size of the block chain
	public static int getSize() {
		return BlockChain.size();
	}

	//Add verified block to the block chain, multicast to all processes
	public static void addToBlockChain(BlockRecord block) {
		BlockChain.add(block);
		Blockchain.getInstance().multicastBlockChain(BlockChain);
	}

	//Updates the blockchain for this process
	public static void updateBlockChain(ArrayList<BlockRecord> updatedBlockChain) {
		int blockNum = 1;
		for(BlockRecord r : updatedBlockChain) {
			r.setBlockNum(String.valueOf(blockNum));
			blockNum++;
		}
		BlockChain = updatedBlockChain;
	}

	//Returns true if Blockchain contains this block, determined by the UUIN
	public static boolean blockChainContainsBlock(BlockRecord block) {
		for(BlockRecord r : BlockChain) {
			if(r.getblockUUIN().equals(block.getblockUUIN())) {
				return true;
			}
		}
		return false;
	}

	//returns the hash value of the most recent record in the blockchain
	public static String getPrevBlockHash() {
		if(BlockChain.isEmpty())
			return Blockchain.blockChainStart;
		return BlockChain.get(BlockChain.size()-1).getSHA256();
	}

	//Process for verifying the blockchain
	public static void verifyBlockChain(String request) {
		try {
			String hash;
			int workNumber = 0;
			String prevHash = Blockchain.blockChainStart; //hash value of previous block, initialized with our dummy string
			Signature sig = Signature.getInstance("SHA1WithRSA");
			for(BlockRecord r : BlockChain) {

				//generates a SHA256 hash from concatenated data of current block, the previous hash, and the random string
				hash = Blockchain.generateHash(r.getConcatData(),prevHash,r.getRandomString());
				prevHash = hash;
				if(request.equals("hash") || request.equals("fullVerification")) {
					//If this hash does not equal to the SHA256 string of this block, verification failed
					if(!hash.equals(r.getSHA256())) {
						System.out.println("Verification for Block " + r.getBlockNum() + " failed: "
								+ "SHA256 hash does not match. All following blocks are invalid.");
						return;
					}
				}
				if(request.equals("threshold") || request.equals("fullVerification")) {
					workNumber = Integer.parseInt(hash.substring(0,4),16);
					if(!(workNumber < 20000)) {
						System.out.println("Verification for Block " + r.getBlockNum() + " failed: "
								+ "SHA256 confirmed, but does not meet work threshold. All following blocks are invalid.");
						return;
					}
				}

				//------------------ checks to see if this block was signed by its verifying process -------------//
				if(request.equals("signature") || request.equals("fullVerification")) {
					sig.initVerify(Blockchain.publicKeys.get(Integer.parseInt(r.getVerificationProcessId())));
					sig.update(r.getSHA256().getBytes());
					if(!sig.verify(Base64.getDecoder().decode(r.getSignedSHA256()))){
						System.out.println("Verification for Block " + r.getBlockNum() + " failed: "
								+ "signature does not match the verifying process. All following blocks are invalid.");
						return;
					}

					//---------------------- checks to see if this block was signed by its creator process -------------//

					sig.initVerify(Blockchain.publicKeys.get(Integer.parseInt(r.getCreatingProcess())));
					sig.update(r.getblockUUIN().getBytes());
					if(!sig.verify(Base64.getDecoder().decode(r.getSignedUUIN()))){
						System.out.println("Verification for Block " + r.getBlockNum() + " failed: "
								+ "signature does not match the creating process. All following blocks are invalid.");
						return;
					}
				}
			}
			//If none of the above conditions were met for any record in the block chain, print success to console
			if(request.equals("hash")) {
				System.out.println("Blocks 1-" + BlockChain.get(BlockChain.size() - 1).getBlockNum() + " in the "
						+ "blockchain have been verified based on hash criteria.");
			}
			else if (request.equals("threshold")) {
				System.out.println("Blocks 1-" + BlockChain.get(BlockChain.size() - 1).getBlockNum() + " in the "
						+ "blockchain have been verified based on threshold criteria.");
			}
			else if (request.equals("signature")) {
				System.out.println("Blocks 1-" + BlockChain.get(BlockChain.size() - 1).getBlockNum() + " in the "
						+ "blockchain have been verified based on signature criteria.");
			}
			else {
				System.out.println("Blocks 1-" + BlockChain.get(BlockChain.size() - 1).getBlockNum() + " in the "
						+ "blockchain have been verified.");
			}
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (NumberFormatException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (SignatureException e) {
			e.printStackTrace();
		}
	}

	//Prints to console which process verified each block
	public static void credit() {
		String P0 = "P0: ";
		String P1 = "P1: ";
		String P2 = "P2: ";
		for(BlockRecord r : BlockChain) {
			if(r.getVerificationProcessId().equals("0")) {
				P0 = P0 + r.getBlockNum() + ", ";
			}
			else if(r.getVerificationProcessId().equals("1")) {
				P1 = P1 + r.getBlockNum() + ", ";
			}
			else if(r.getVerificationProcessId().equals("2")) {
				P2 = P2 + r.getBlockNum() + ", ";
			}
		}
		System.out.println(P0);
		System.out.println(P1);
		System.out.println(P2);
	}

	//Lists information of each block in the blockchain
	public static void list() {
		String list = "";
		for(int j = BlockChain.size() - 1; j >= 0; j--){
			list = list + BlockChain.get(j).getBlockNum() + " ";
			list = list + BlockChain.get(j).getTimeStamp() + " ";
			list = list + BlockChain.get(j).getFName() + " ";
			list = list + BlockChain.get(j).getLName() + " ";
			list = list + BlockChain.get(j).getDiagnosis() + " ";
			list = list + BlockChain.get(j).getTreatment() + " ";
			list = list + BlockChain.get(j).getMedicine() + " ";
			list = list + "\n";
		}
		System.out.println(list);
	}
}

//Blockchain class, holds public keys, multicast methods, string generation methods
public class Blockchain {
	private static volatile Blockchain instance = null;		//singleton instance
	static int PID;											//Process ID
	static boolean begin;									//boolean determing when process 0 and 1 can start									
	static String serverName = "localhost";					//names of our server (local computer)
	static int numProcesses = 3;							//total number of processes
	static String blockChainStart;							//dummy string that initializes the block chain
	static HashMap<Integer,PublicKey> publicKeys;			//hashmap for storing public keys
	private static final String ALPHA_NUMERIC_STRING = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
	private static PrivateKey privateKey;					//private key of this process
	private static PublicKey publicKey;						//public key of this process

	//private c'tor
	private Blockchain() {}

	//get singleton instance
	public static Blockchain getInstance() {
		if (instance == null) {
			synchronized(Blockchain.class) {
				if (instance == null) {
					instance = new Blockchain();
				}
			}
		}
		return instance;
	}

	//returns private key of this process
	public PrivateKey getPrivateKey() {
		return privateKey;
	}

	//initializes the hashmap these stores public keys
	public static void initializePublicKeys() {
		publicKeys = new HashMap<Integer,PublicKey>();
	}

	//Generates the key public/private keys for this process
	public void generateKeyPairs() {
		try {
			KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
			SecureRandom random = SecureRandom.getInstance("SHA1PRNG", "SUN");
			keyGen.initialize(1024, random);
			KeyPair pair = keyGen.generateKeyPair();
			privateKey = pair.getPrivate();
			publicKey = pair.getPublic();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			e.printStackTrace();
		}
	}

	//Encodes the public key
	public String base64Encode() {
		return Base64.getEncoder().encodeToString(publicKey.getEncoded());
	}

	//Sends out public keys to all other processes
	public void multiCastPublicKeys() {
		generateKeyPairs();
		String encodedKey = base64Encode();
		Socket sock;
		PrintStream toServer;
		try {
			for(int i = 0; i < numProcesses; i++) {
				sock = new Socket(serverName, 4710 + i);
				toServer = new PrintStream(sock.getOutputStream());
				toServer.println(encodedKey + " " + PID); toServer.flush();
				sock.close();
			}
		} catch (UnknownHostException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}

	}

	//Multicasts unverified block to all other processes
	public void multicastUnverifiedBlock(BlockRecord block) {

		try {
			Socket sock;
			PrintStream toServer;
			JAXBContext jaxbContext = JAXBContext.newInstance(BlockRecord.class);
			Marshaller jaxbMarshaller;
			jaxbMarshaller = jaxbContext.createMarshaller();
			StringWriter sw = new StringWriter();
			jaxbMarshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);
			jaxbMarshaller.marshal(block,sw);
			String blockXML = sw.toString();
			System.out.println("Data read into block: ");
			System.out.println(blockXML);
			for(int i = 0; i < numProcesses; i++) {
				sock = new Socket(serverName, 4820 + i);
				toServer = new PrintStream(sock.getOutputStream());
				toServer.println(blockXML); toServer.flush();
				sock.close();
			}
		} catch (UnknownHostException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		} catch (JAXBException e) {
			e.printStackTrace();
		}
	}

	//Multicasts updated blockchain to all processes
	public void multicastBlockChain(ArrayList<BlockRecord> blockchain) {
		try {
			Socket sock;
			PrintStream toServer;
			JAXBContext jaxbContext = JAXBContext.newInstance(Ledger.class);
			Marshaller jaxbMarshaller;
			jaxbMarshaller = jaxbContext.createMarshaller();
			StringWriter sw = new StringWriter();
			jaxbMarshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);
			jaxbMarshaller.marshal(new Ledger(blockchain),sw);
			String blockChainXML = sw.toString();
			for(int i = 0; i < numProcesses; i++) {
				sock = new Socket(serverName, 4930 + i);
				toServer = new PrintStream(sock.getOutputStream());
				toServer.println(blockChainXML); toServer.flush();
				sock.close();
			}
		} catch (UnknownHostException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		} catch (JAXBException e) {
			e.printStackTrace();
		}
	}

	//Adds public key/process ID  key-value pair to hash map
	public void addKeys(PublicKey key, int process) {
		publicKeys.putIfAbsent(process,key);
	}

	//Puts data read from file into an unverified block
	public static BlockRecord dataIntoBlock(String line){
		BlockRecord unverifiedBlock = new BlockRecord();
		String [] data = line.split(" ");
		unverifiedBlock.setUUID(UUID.randomUUID().toString());

		//--------------- Creating Process signs this block's UUIN -------------------------------//
		try {
			byte[] signedUUIN = unverifiedBlock.getblockUUIN().getBytes();
			Signature sig = Signature.getInstance("SHA1WithRSA");
			sig.initSign(privateKey);
			sig.update(signedUUIN);
			byte[] signatureBytes = sig.sign();
			unverifiedBlock.setSignedUUIN(Base64.getEncoder().encodeToString(signatureBytes));
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (SignatureException e) {
			e.printStackTrace();
		} 
		unverifiedBlock.setFName(data[0]);
		unverifiedBlock.setLName(data[1]);
		unverifiedBlock.setDoB(data[2]);
		unverifiedBlock.setSSN(data[3]);
		unverifiedBlock.setDiagnosis(data[4]);
		unverifiedBlock.setTreatment(data[5]);
		unverifiedBlock.setMedicine(data[6]);
		unverifiedBlock.setCreatingProcess(String.valueOf(PID));
		unverifiedBlock.setTimeStamp(new SimpleDateFormat("HH.mm.ss").format(new Date()));
		return unverifiedBlock;
	}

	//Generates a random alpha-numeric string of size 'count'
	public static String randomAlphaNumeric(int count) {
		StringBuilder builder = new StringBuilder();
		while (count-- != 0) {
			int character = (int)(Math.random()*ALPHA_NUMERIC_STRING.length());
			builder.append(ALPHA_NUMERIC_STRING.charAt(character));
		}
		return builder.toString();
	}

	//Concatenates the given parameters and creates a SHA256 hashed string
	public static String generateHash(String data, String prevHash,String randomString) {
		String concatString = randomString + data + prevHash; // Concatenate with our input string (which represents Blockdata)
		try {
			MessageDigest MD = MessageDigest.getInstance("SHA-256");
			byte[] bytesHash = MD.digest(concatString.getBytes("UTF-8")); // Get the hash value
			String stringOut = DatatypeConverter.printHexBinary(bytesHash);
			return stringOut;
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		}
		return null;
	}

	//Builds the blockchain ledger in xml
	public static void buildXML() {

		try {
			JAXBContext jaxbContext = JAXBContext.newInstance(Ledger.class);
			Marshaller jaxbMarshaller;
			jaxbMarshaller = jaxbContext.createMarshaller();
			jaxbMarshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);
			jaxbMarshaller.marshal(new Ledger(),new File("BlockchainLedger.xml"));
		} catch (PropertyException e) {
			e.printStackTrace();
		} catch (JAXBException e) {
			e.printStackTrace();
		}
	}

	public static void main(String args[]) {
		PID = (args.length < 1) ? 0 : Integer.parseInt(args[0]); //set PID
		Comparator<BlockRecord> comp = new TimeStampComparator(); //comparator that will override priority queue built in comparator
		BlockingQueue<BlockRecord> queue = new PriorityBlockingQueue<>(10,comp); // initialize concurrent queue for blocks
		new Ports().setPorts(); 		// Set port numbers based on process ID
		blockChainStart = "A3WXGY45";	// Random dummy string I made up to initialize blockchain
		Ledger.initializeBlockChain();  //Initializes the blockchain ArrayList
		initializePublicKeys();			//Initializes the public keys HashMap 
		new Thread(new PublicKeyServer()).start(); // Create a thread to handle incoming public keys
		new Thread(new UnverifiedBlockServer(queue)).start(); // Create a thread to handle incoming unverified blocks
		new Thread(new BlockchainServer()).start(); // Create a thread to handle incoming blockchains

		//Process 0 and Process 1 wait for Process 2 to send them their public key
		if(PID != 2) {
			begin = false;
			while(begin == false) {
				if(!publicKeys.isEmpty()) {
					begin = true;
				}
				try{Thread.sleep(1000);}catch(Exception e1){} // Wait for process 2 to send their public key.
			}
		}
		new Blockchain().multiCastPublicKeys();				//send out public key to all processes

		// wait for all public keys to be received
		while(publicKeys.size() != 3) {
			try{Thread.sleep(1000);}catch(Exception e1){}
		}
		System.out.println("Process " + PID + " reading in data from BlockInput" + PID + ".txt");
		System.out.println();
		System.out.println("Console Commands: ");
		System.out.println("V :  Verify Blockchain");
		System.out.println("C :  Block Record Credit");
		System.out.println("R Filename : Read in file data");
		System.out.println("L :  List block on console");

		// Create a thread which handles unverified blocks inserted into the priority queue
		new Thread(new UnverifiedBlockConsumer(queue)).start();

		//Process reads data from input file
		try {
			File file = new File("BlockInput" + PID + ".txt");
			FileReader fileReader = new FileReader(file.getCanonicalPath());
			BufferedReader br =  new BufferedReader(fileReader);

			String line;
			while((line = br.readLine()) != null) {
				BlockRecord unverifiedBlock = dataIntoBlock(line);			//Insert data from file into BlockRecord
				getInstance().multicastUnverifiedBlock(unverifiedBlock);	//multicast this unverified block to all processes
			}
			br.close();
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
		Scanner scan = new Scanner(System.in);
		String input;

		//Based on user input, perform relevant action
		while(true) {	

			input = scan.nextLine();

			if (input.contains("V")) {
				String verRequest = "";
				String[] data = input.split(" ");
				if(data.length == 1) {
					verRequest = "fullVerification";
				}
				else if(data[1].equals("threshold")) {
					verRequest = "threshold";
				}
				else if(data[1].equals("hash")) {
					verRequest = "hash";
				}
				else if(data[1].equals("signature")) {
					verRequest = "signature";
				}
				Ledger.verifyBlockChain(verRequest);
			}
			else if(input.equals("C")) {
				Ledger.credit();
			}
			else if(input.equals("L")) {
				Ledger.list();
			}
			else if(input.contains("R ")) {
				try {
					String filename = input.split(" ")[1];
					File file = new File(filename);
					FileReader fileReader = new FileReader(file.getCanonicalPath());
					BufferedReader br =  new BufferedReader(fileReader);
					String line;
					while((line = br.readLine()) != null) {
						BlockRecord unverifiedBlock = dataIntoBlock(line);
						getInstance().multicastUnverifiedBlock(unverifiedBlock);
					}
				} catch (FileNotFoundException e) {
					e.printStackTrace();
				} catch (IOException e) {
					e.printStackTrace();
				}
			}
		}
	}
}