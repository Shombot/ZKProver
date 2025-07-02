package examples;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Base64;
import java.util.Date;
import java.util.Base64.Decoder;

import javax.net.ServerSocketFactory;
import javax.net.SocketFactory;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocketFactory;

import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketAddress;
import java.security.SecureRandom;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

import curve_wrapper.BouncyCastleCurve;
import curve_wrapper.BouncyCastlePoint;
import curve_wrapper.ECCurveWrapper;
import curve_wrapper.ECPointWrapper;
import zero_knowledge_proofs.ArraySizesDoNotMatchException;
import zero_knowledge_proofs.DLPedersenCommitment;
import zero_knowledge_proofs.DLSchnorrProver;
import zero_knowledge_proofs.ECPedersenCommitment;
import zero_knowledge_proofs.ECSchnorrProver;
import zero_knowledge_proofs.MultipleTrueProofException;
import zero_knowledge_proofs.NoTrueProofException;
import zero_knowledge_proofs.ZKPProtocol;
import zero_knowledge_proofs.ZKToolkit;
import zero_knowledge_proofs.ZeroKnowledgeAndProver;
import zero_knowledge_proofs.ZeroKnowledgeOrProver;
import zero_knowledge_proofs.CryptoData.BigIntData;
import zero_knowledge_proofs.CryptoData.CryptoData;
import zero_knowledge_proofs.CryptoData.CryptoDataArray;
import zero_knowledge_proofs.CryptoData.ECCurveData;
import zero_knowledge_proofs.CryptoData.ECPointData;

public class AADProverBasicECSchnorrORExample {
	public static void main(String[] args) throws IOException, ClassNotFoundException, MultipleTrueProofException, NoTrueProofException, ArraySizesDoNotMatchException, InterruptedException {
		int n = 50;
		int i_real = 29;
		
		System.setProperty("javax.net.ssl.trustStore", "resources/Client_Truststore");
		System.setProperty("javax.net.ssl.keyStore", "resources/Server_Keystore");
		System.setProperty("javax.net.ssl.trustStorePassword", "test123");
		System.setProperty("javax.net.ssl.keyStorePassword", "test123");
		System.setProperty("java.security.policy", "resources/mysecurity.policy");
		ServerSocketFactory ssf = ServerSocketFactory.getDefault();
		SocketFactory sf = SocketFactory.getDefault();
		Decoder decoder = Base64.getDecoder();
		
		System.out.println(new Date());
		

		if(args.length != 2) {
			System.out.println("No args, defaulting to [127.0.0.1, 5001]");
			args = new String[2];
			args[0] = "127.0.0.1";
			args[1] = "5001";
		}
		
		
		ServerSocket host = null;
		Socket s;
		ObjectInputStream in;
		ObjectOutputStream out;
		try {
			SocketAddress dest = new InetSocketAddress(args[0], Integer.parseInt(args[1]));
			s = sf.createSocket();
			s.connect(dest);
			System.out.println("Connection to Server successful");
			in = new ObjectInputStream(s.getInputStream());
			out = new ObjectOutputStream(s.getOutputStream());
		}
		catch(Exception e){
			System.out.println("Connection not open, opening server");
			try {
				host = ssf.createServerSocket(Integer.parseInt(args[1]));
				s = host.accept();
				if(args[0].equals(s.getInetAddress().getHostAddress())){
					System.out.println("");
				}
				System.out.println("Connection established");
				out = new ObjectOutputStream(s.getOutputStream());
				in = new ObjectInputStream(s.getInputStream());
			}
			
			catch( java.net.BindException ex)
			{
				SocketAddress dest = new InetSocketAddress(args[0], Integer.parseInt(args[1]));
				s = sf.createSocket();
				s.connect(dest);
				System.out.println("Connection to Server successful");
				in = new ObjectInputStream(s.getInputStream());
				out = new ObjectOutputStream(s.getOutputStream());
			}
		}
		
		SecureRandom rand = new SecureRandom();

		ECPoint gUnwrapped = ECNamedCurveTable.getParameterSpec("secp256k1").getG();
		ECCurve cUnwrapped = gUnwrapped.getCurve();	
		BigInteger order = cUnwrapped.getOrder();
		ECPointWrapper g = new BouncyCastlePoint(gUnwrapped);
		ECCurveWrapper c = new BouncyCastleCurve(cUnwrapped); //up to this point, they are the same
		ECPointWrapper h = g.multiply(ZKToolkit.random(order, rand));
		
		out.writeObject(h.getEncoded(true));
		out.flush();
		
		BigInteger[] x = new BigInteger[n];
		ECPointWrapper[] y = new ECPointWrapper[n];
		
		for(int i = 0; i < n; i++) {
			x[i] = ZKToolkit.random(order, rand);
			y[i] = g.multiply(x[i]);
			out.writeObject(y[i].getEncoded(true));
		}

		out.flush();
		
		ZKPProtocol proof;
		{
			ZKPProtocol[] inners = new ZKPProtocol[n];
			for(int i = 0; i < n; i++) {
				inners[i] = new ECSchnorrProver();
			}
			
			proof = new ZeroKnowledgeOrProver(inners, order);
		}
		
		/*
		ZKPProtocol proof;
		{
			ZKPProtocol innerProof = new ECSchnorrProver();
			ZKPProtocol[] inner = new ZKPProtocol[] {innerProof, innerProof};
			
			proof = new ZeroKnowledgeOrProver(inner, order);
		}
		*/
		
		/*
		 * Three main things needed for the proof.
		 *   1.  Public inputs  -- Prover and Verifier
		 *   2.  Secrets        -- Prover
		 *   3.  Environment    -- Prover and Verifier
		 */
		
		//Create Public Inputs
		CryptoData publicInputs;
		{
			CryptoDataArray[] pub = new CryptoDataArray[n];
			for(int i = 0; i < n; i++) {
				CryptoData[] inner = new CryptoData[1];
				inner[0] = new ECPointData(y[i]);
				pub[i] = new CryptoDataArray(inner);
			}
			publicInputs = new CryptoDataArray(pub);
		}
		
		/*
		CryptoData publicInputs;
		{
			CryptoData[] inner1 = new CryptoData[1];
			CryptoData[] inner2 = new CryptoData[1];
			inner1[0] = new ECPointData(y1);
			inner2[0] = new ECPointData(y2);
			publicInputs = new CryptoDataArray(new CryptoDataArray[] {new CryptoDataArray(inner1), new CryptoDataArray(inner2)});
		}
		 */
		//Prover will create secrets section
		
		/*
		CryptoData secrets;
		{
			BigInteger r1 = ZKToolkit.random(order, rand);
			BigInteger r2 = ZKToolkit.random(order, rand);
			BigInteger[] inner1 = new BigInteger[] {r1};
			BigInteger[] inner2 = new BigInteger[] {r2, x2};
			BigInteger[] simChal = new BigInteger[] {ZKToolkit.random(order, rand), null}; //null means its the real protocol
			secrets = new CryptoDataArray(new CryptoDataArray[] {new CryptoDataArray(inner1), new CryptoDataArray(inner2), new CryptoDataArray(simChal)});
		}*/
		
		CryptoData secrets;
		BigInteger[] simChallenges = new BigInteger[n];
		CryptoData[] secretsTemp = new CryptoData[n + 1];
		{
			for(int i = 0; i < n; i++) {
				if(i == i_real) { //inside the loop is copied from GPT
					BigInteger r = ZKToolkit.random(order, rand);
			        secretsTemp[i] = new CryptoDataArray(new BigInteger[] {r, x[i]});
			        simChallenges[i] = null; // null means "real proof"
				} else {
					BigInteger fakeR = ZKToolkit.random(order, rand);
					secretsTemp[i] = new CryptoDataArray(new BigInteger[] {fakeR});
					simChallenges[i] = ZKToolkit.random(order,  rand); //fake proof since this is not null
				}
			}
			secretsTemp[n] = new CryptoDataArray(simChallenges);
		}
		secrets = new CryptoDataArray(secretsTemp); //This secrets section is most likely to be prone to errors
		
		//Create Environment
		/*
		CryptoData env;	
		{
			CryptoData[] inner = new CryptoData[] {new ECCurveData(c, g)};
			env = new CryptoDataArray(new CryptoDataArray[] {new CryptoDataArray(inner), new CryptoDataArray(inner)});
		}
		*/
		
		CryptoData env;	
		CryptoData[] envTemp = new CryptoDataArray[n];
		{
			CryptoData[] inner = new CryptoData[] {new ECCurveData(c, g)};
			for(int i = 0; i < n; i++) {
				envTemp[i] = new CryptoDataArray(inner);
			}
			env = new CryptoDataArray(envTemp);
		}
		
		/*
		CryptoData commEnv;
		{
			CryptoData[] inner = new CryptoData[] {new ECCurveData(c, g), new ECPointData(h)};
			commEnv = new CryptoDataArray(inner);
		}*/
		
		CryptoData commEnv;
		{
			CryptoData[] inners = new CryptoData[n];
			for(int i = 0; i < n; i++) {
				if(i == i_real) {
					inners[i] = new ECPointData(h);
				} else {
					inners[i] = new ECCurveData(c, g);
				}
			}
			commEnv = new CryptoDataArray(inners);
		}
		
		proof.trueZKProve(publicInputs, secrets, env, commEnv, in, out);
		
		CryptoData[] transcript = proof.proveFiatShamir(publicInputs, secrets, env);
		
		System.out.println(transcript[0]);
		
		out.writeObject(transcript);
		out.flush();
		
	}
}
