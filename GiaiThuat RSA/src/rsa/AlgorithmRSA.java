package rsa;

import java.math.BigInteger;
import java.security.SecureRandom;

public class AlgorithmRSA {
//d: private key, e: public key
    private BigInteger n, d, e;
   

    public BigInteger getN() {
        return n;
    }

    public void setN(BigInteger n) {
        this.n = n;
    }

    public BigInteger getD() {
        return d;
    }

    public void setD(BigInteger d) {
        this.d = d;
    }

    public BigInteger getE() {
        return e;
    }

    public void setE(BigInteger e) {
        this.e = e;
    }

    /**
     * Create an instance that can encrypt using someone elses public key.
     */
    public AlgorithmRSA(BigInteger n1, BigInteger e1) {
        n = n1;
        e = e1;
    }

    /**
     * Create an instance that can both encrypt and decrypt.
     */
    public AlgorithmRSA() {
        
       
    }
    
    public void KeyRSA(int bits){
        
        
        SecureRandom r = new SecureRandom();//create BigInteger r random
        BigInteger p = new BigInteger(bits , 100, r);
        BigInteger q = new BigInteger(bits , 100, r);
        n = p.multiply(q);
        BigInteger m = (p.subtract(BigInteger.ONE)).multiply(q
                .subtract(BigInteger.ONE));
        boolean check = false;
        do {
            e = new BigInteger(bits , 50, r);
            if (m.gcd(e).equals(BigInteger.ONE) && e.compareTo(m) < 0) {
                check = true;
            }
        } while (!check);
        d = e.modInverse(m);
        
    }


    // Encrypt the given plaintext message.Use public key decrypt
   
    
    public synchronized String encrypt(String str) {
        return (new BigInteger(str.getBytes())).modPow(e, n).toString();
    }

   
    //Encrypt the given plaintext message.Use public key decrypt
 
    public synchronized BigInteger encrypt(BigInteger b) {
        return b.modPow(e, n);
    }

  
     // Decrypt the given ciphertext message.Use private key decrypt
   
    public synchronized String decrypt(String str) {
        return new String((new BigInteger(str)).modPow(d, n).toByteArray());
    }

  
     // Decrypt the given ciphertext message.Use private key decrypt
 
    public synchronized BigInteger decrypt(BigInteger b) {
        return b.modPow(d, n);
    }

 

     
   
    
    
}
