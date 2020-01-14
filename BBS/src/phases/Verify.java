/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package phases;


import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;

/**
 * This class is accessed by a Group member of same group or another group
 * <P> Any entity which possesses group public key can use this class to verify 
 * the validity of group signature
@author Vivek Agrawal<vivek.agrawal@harman.com>
 */
public class Verify {

    /**
     * 
     * @param thePairing The Pairing interface provides the methods to access the
     * algebraic structures (G1, G2, GT, Zr) involved in the pairing computation.
     * @param signature The signature whose validity is being checked
     * @param GPK The public key of group
     * @param msg The secret key of group
     * @return result of verification in terms of true/false
     */
    public static boolean BBSVerify(Pairing thePairing, byte[] signature, HashMap<String, Element> GPK, String msg) {

        // System.out.println("--------\nVerify part\n"+new String(signature));
        Element T1 = thePairing.getG1().newElement();
        Element T2 = thePairing.getG1().newElement();
        Element T3 = thePairing.getG1().newElement();
        
        Element salpha = thePairing.getZr().newElement();
        Element sbhta = thePairing.getZr().newElement();
        Element sx = thePairing.getZr().newElement();
        Element sdelta1 = thePairing.getZr().newElement();
        Element sdelta2 = thePairing.getZr().newElement();
        Element c = thePairing.getZr().newElement();


        byte[] myHash = null;
        MessageDigest hash = null;
        try {
            hash = MessageDigest.getInstance("SHA-1");
        } catch (NoSuchAlgorithmException ex) {
        }

        hash.update(msg.getBytes());
        myHash = hash.digest();

        Element M = thePairing.getG1().newElement().setFromHash(myHash, 0, myHash.length);


        int pointerInSignature = T1.setFromBytes(signature, 0);
        pointerInSignature += T2.setFromBytes(signature, pointerInSignature);
        pointerInSignature += T3.setFromBytes(signature, pointerInSignature);
        pointerInSignature += c.setFromBytes(signature, pointerInSignature);
        pointerInSignature += salpha.setFromBytes(signature, pointerInSignature);
        pointerInSignature += sbhta.setFromBytes(signature, pointerInSignature);
        pointerInSignature += sx.setFromBytes(signature, pointerInSignature);
        pointerInSignature += sdelta1.setFromBytes(signature, pointerInSignature);
        pointerInSignature += sdelta2.setFromBytes(signature, pointerInSignature);


        T1 = T1.getImmutable();
        T2 = T2.getImmutable();
        T3 = T3.getImmutable();
        c = c.getImmutable();
        salpha = salpha.getImmutable();
        sbhta = sbhta.getImmutable();
        sx = sx.getImmutable();
        sdelta1 = sdelta1.getImmutable();
        sdelta2 = sdelta2.getImmutable();

        Element tmp, tmp1, tmp2;

        // construction of R1 = u^salpha * T1^(-c)
        tmp = c.negate();
        tmp1 = T1.powZn(tmp);
        tmp2 = (Element) GPK.get("u");
        tmp2 = tmp2.powZn(salpha);
        Element R1 = tmp2.mul(tmp1);

        // construction of R2 = v^sbeta * T2^(-c)
      
        tmp1 = T2.powZn(tmp);
        tmp2 = (Element) GPK.get("v");
        tmp2 = tmp2.powZn(sbhta);
        Element R2 = tmp2.mul(tmp1);

        // consruction of R4 = T1^sx * u^(-sdelta1)
        tmp = sdelta1.negate();
        tmp1 = T1.powZn(sx);
        tmp2 = (Element) GPK.get("u");
        tmp2 = tmp2.powZn(tmp);
        Element R4 = tmp2.mul(tmp1);

        // construction of R5 = T2^sx * v^(-sdelta2)
        tmp = sdelta2.negate();
        tmp1 = T2.powZn(sx);
        tmp2 = (Element) GPK.get("v");
        tmp2 = tmp2.powZn(tmp);
        Element R5 = tmp2.mul(tmp1);

        // construction of  R3 = e(T3,g2)^sx *
        // e(h,w)^(-sa-sb)*e(h,g2)^(-sdelta1-sdelta2) *
        // * (e(T3,w)/e(g1,g2))^c

        tmp = thePairing.pairing(T3, (Element) GPK.get("g2"));
        tmp = tmp.powZn(sx);

        tmp1 = thePairing.pairing((Element) GPK.get("h"), (Element) GPK.get("w"));
        tmp1 = tmp1.powZn(salpha.add(sbhta).negate());

        tmp2 = thePairing.pairing((Element) GPK.get("h"), (Element) GPK.get("g2"));
        tmp2 = tmp2.powZn(sdelta1.add(sdelta2).negate());

        Element tmp3 = thePairing.pairing(T3, (Element) GPK.get("w"));
        tmp3 = tmp3.div(thePairing.pairing((Element) GPK.get("g1"), (Element) GPK.get("g2")));
        tmp3 = tmp3.powZn(c);

        tmp = tmp.mul(tmp1);
        tmp = tmp.mul(tmp2);
        tmp = tmp.mul(tmp3);

        Element R3 = tmp;


        int intLengthBytes = M.getLengthInBytes() + T1.getLengthInBytes() + T2.getLengthInBytes() + T3.getLengthInBytes() + R1.getLengthInBytes() + R2.getLengthInBytes() + R3.getLengthInBytes()
                + R4.getLengthInBytes() + R5.getLengthInBytes();

        byte[] hash_buf = new byte[intLengthBytes];
        int offset = 0;
        System.arraycopy(M.toBytes(), 0, hash_buf, 0, M.getLengthInBytes());
        offset += M.getLengthInBytes();
        System.arraycopy(T1.toBytes(), 0, hash_buf, offset, T1.getLengthInBytes());
        offset += T1.getLengthInBytes();
        System.arraycopy(T2.toBytes(), 0, hash_buf, offset, T2.getLengthInBytes());
        offset += T2.getLengthInBytes();
        System.arraycopy(T3.toBytes(), 0, hash_buf, offset, T3.getLengthInBytes());
        offset += T3.getLengthInBytes();
        System.arraycopy(R1.toBytes(), 0, hash_buf, offset, R1.getLengthInBytes());
        offset += R1.getLengthInBytes();
        System.arraycopy(R2.toBytes(), 0, hash_buf, offset, R2.getLengthInBytes());
        offset += R2.getLengthInBytes();
        System.arraycopy(R3.toBytes(), 0, hash_buf, offset, R3.getLengthInBytes());
        offset += R3.getLengthInBytes();
        System.arraycopy(R4.toBytes(), 0, hash_buf, offset, R4.getLengthInBytes());
        offset += R4.getLengthInBytes();
        System.arraycopy(R5.toBytes(), 0, hash_buf, offset, R5.getLengthInBytes());

//           System.out.println("\nVerify phase is-------\nT1: " + new String(T1.toString()) + "-------\nT2: " + new String(T2.toString()) + "-------\nT3: " + new String(T3.toString())
//                + "-------\nM: " + new String(M.toString()) + "-------\nR1: " + new String(R1.toString()) + "-------\nR2: " + new String(R2.toString()) + "  s " + R2.getLengthInBytes() + "-------\nR3: "
//                + new String(R3.toString()) + R2.getLengthInBytes() + "-------\nR4: " + new String(R4.toString()) + "-------\nR5: "
//                + new String(R5.toString()));

        // creation of hash
        MessageDigest hash1 = null;
        try {
            hash1 = MessageDigest.getInstance("SHA-1");
        } catch (NoSuchAlgorithmException ex) {
        }

        hash1.update(hash_buf);
        byte[] digest = hash1.digest();

        Element c_created = thePairing.getZr().newElement().setFromHash(digest, 0, digest.length);
     
        // check the generated hash and received hash are same or not
        if (c_created.isEqual(c)) {
            return true;
        } else {
            return false;
        }
    }
}
