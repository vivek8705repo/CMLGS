/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package phases;

import generic.Stopwatch;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

/**
 * This class is accessed by a Group member to create group signature.
 *@author Vivek Agrawal<vivek.agrawal@harman.com>
 */
public class Sign {

    protected static byte[] signature;

    /**
     * This method signs a message and generates group signature on it
     * @param thePairing The Pairing interface provides the methods to access the
     * algebraic structures (G1, G2, GT, Zr) involved in the pairing computation.
     * @param GPK The public key of group
     * @param GSK The secret key of member
     * @param msg The message which is to be signed
     * @return signature on the given message
     */
    public static byte[] BBSSign(Pairing thePairing, HashMap<String, Element> GPK, HashMap<String, Element> GSK, String msg) {
         List<Long> time_sign = new ArrayList<Long>();
        Stopwatch timer_sign = new Stopwatch().start();
        Element c;
        BigInteger temp;
        int intLengthBytes;
        Element ralpha, rbhta, rx, rdelta1, rdelta2, alpha, bhta, T1, T2, T3, R1,
                R2, R3, R4, R5, R3_pre, R3_a, R3_b, R3_c, tmp;
        byte[] myHash;
        int offset;
        do {
            offset = 0;
            myHash = null;
            alpha = thePairing.getZr().newRandomElement().getImmutable();
            bhta = thePairing.getZr().newRandomElement().getImmutable();
            T1 = thePairing.getG1().newElement();
            T2 = thePairing.getG1().newElement();
            T3 = thePairing.getG1().newElement();
            R1 = thePairing.getG1().newElement();
            R2 = thePairing.getG1().newElement();
            R3 = thePairing.getGT().newElement();
            R3_pre = thePairing.getGT().newElement();

            R3_a = thePairing.getGT().newElement();
            R3_b = thePairing.getGT().newElement();
            R3_c = thePairing.getGT().newElement();

            R4 = thePairing.getG1().newElement();
            R5 = thePairing.getG1().newElement();

            tmp = (Element) GPK.get("u");


            T1 = tmp.powZn(alpha).getImmutable();

            Element tmp1 = (Element) GPK.get("v");
            T2 = tmp1.powZn(bhta).getImmutable();

            tmp = alpha.add(bhta);
            T3 = (Element) GPK.get("h");
            T3 = T3.powZn(tmp);


            T3 = T3.mul((Element) GSK.get("A")).getImmutable();

 

            ralpha = thePairing.getZr().newRandomElement().getImmutable();
            rbhta = thePairing.getZr().newRandomElement().getImmutable();
            rx = thePairing.getZr().newRandomElement().getImmutable();
            rdelta1 = thePairing.getZr().newRandomElement().getImmutable();
            rdelta2 = thePairing.getZr().newRandomElement().getImmutable();

            tmp = (Element) GPK.get("u");
            R1 = tmp.powZn(ralpha).getImmutable();
            tmp = (Element) GPK.get("v");
            R2 = tmp.powZn(rbhta).getImmutable();

         

            tmp = (Element) GPK.get("pair_h_g2");
            R3_a = tmp.powZn(alpha.add(bhta)).mul((Element) GSK.get("pair_A_g2")).powZn(rx);
            R3_b = (Element) GPK.get("pair_h_w");
            R3_b = R3_b.powZn(ralpha.add(rbhta).negate());
            R3_c = (Element) GPK.get("pair_h_g2");
            R3_c = R3_c.powZn(rdelta1.add(rdelta2).negate());
            R3 = R3_a.mul(R3_b).mul(R3_c);

            R4 = (Element) GPK.get("u");
            R4 = R4.powZn(rdelta1.negate());
            R4 = R4.mul(T1.powZn(rx)).getImmutable();

            R5 = (Element) GPK.get("v");
            R5 = R5.powZn(rdelta2.negate());
            R5 = R5.mul(T2.powZn(rx)).getImmutable();


            MessageDigest hash = null;
            try {
                hash = MessageDigest.getInstance("SHA-1");
            } catch (NoSuchAlgorithmException ex) {
            }

            hash.update(msg.getBytes());
            myHash = hash.digest();
            Element M = thePairing.getG1().newElement().setFromHash(myHash, 0, myHash.length);
            intLengthBytes = M.getLengthInBytes() + T1.getLengthInBytes() + T2.getLengthInBytes() + T3.getLengthInBytes() + R1.getLengthInBytes() + R2.getLengthInBytes() + R3.getLengthInBytes()
                    + R4.getLengthInBytes() + R5.getLengthInBytes();
//            System.out.println("\nAttributes of Challenge in Signature is-------\nT1: " + new String(T1.toString()) + "-------\nT2: " + new String(T2.toString()) + "-------\nT3: " + new String(T3.toString())
//                    + "-------\nM: " + new String(M.toString()) + "-------\nR1: " + new String(R1.toString()) + "-------\nR2: " + new String(R2.toString()) + "  s " + R2.getLengthInBytes() + "-------\nR3: "
//                    + new String(R3.toString()) + "-------\nR3_pre: " + new String(R3_pre.toString()) + "  s " + R2.getLengthInBytes() + "-------\nR4: " + new String(R4.toString()) + "-------\nR5: "
//                    + new String(R5.toString()));

            byte[] pre_signature = new byte[intLengthBytes];

            System.arraycopy(M.toBytes(), 0, pre_signature, 0, M.getLengthInBytes());
            offset += M.getLengthInBytes();
            System.arraycopy(T1.toBytes(), 0, pre_signature, offset, T1.getLengthInBytes());
            offset += T1.getLengthInBytes();
            System.arraycopy(T2.toBytes(), 0, pre_signature, offset, T2.getLengthInBytes());
            offset += T2.getLengthInBytes();
            System.arraycopy(T3.toBytes(), 0, pre_signature, offset, T3.getLengthInBytes());
            offset += T3.getLengthInBytes();
            System.arraycopy(R1.toBytes(), 0, pre_signature, offset, R1.getLengthInBytes());
            offset += R1.getLengthInBytes();
            System.arraycopy(R2.toBytes(), 0, pre_signature, offset, R2.getLengthInBytes());
            offset += R2.getLengthInBytes();
            System.arraycopy(R3.toBytes(), 0, pre_signature, offset, R3.getLengthInBytes());
            offset += R3.getLengthInBytes();
            System.arraycopy(R4.toBytes(), 0, pre_signature, offset, R4.getLengthInBytes());
            offset += R4.getLengthInBytes();
            System.arraycopy(R5.toBytes(), 0, pre_signature, offset, R5.getLengthInBytes());


            hash.update(pre_signature);
            byte[] myHash2 = hash.digest();
            c = thePairing.getZr().newElement().setFromHash(myHash2, 0, myHash2.length).getImmutable();

            temp = c.toBigInteger();
        } while (temp.compareTo(BigInteger.ZERO) < 0);

        Element salpha = thePairing.getZr().newRandomElement().getImmutable();
        Element sbhta = thePairing.getZr().newRandomElement().getImmutable();
        Element sx = thePairing.getZr().newRandomElement().getImmutable();
        Element sdelta1 = thePairing.getZr().newRandomElement().getImmutable();
        Element sdelta2 = thePairing.getZr().newRandomElement().getImmutable();

        tmp = alpha.mul(c);
        salpha = tmp.add(ralpha);

        tmp = bhta.mul(c);
        sbhta = tmp.add(rbhta);

        tmp = (Element) GSK.get("x");
        tmp = tmp.mul(c);
        sx = rx.add(tmp);


        sdelta1 = alpha.mul(tmp);
        sdelta1 = rdelta1.add(sdelta1);

        sdelta2 = bhta.mul(tmp);
        sdelta2 = rdelta2.add(sdelta2);

//        System.out.println("\nAtrribute of Final Signature-------\nT1: " + new String(T1.toString()) + "-------\nT2: " + new String(T2.toString()) + "-------\nT3: " + new String(T3.toString()) + "-------\nc: "
//                + new String(c.toString()) + "-------\nsalpha: " + new String(salpha.toString()) + "-------\nsbhta: " + new String(sbhta.toString()) + "  s " + sbhta.getLengthInBytes() + "-------\nsx: "
//                + new String(sx.toString()) + "  s " + sx.getLengthInBytes() + "-------\nsdelta1: " + new String(sdelta1.toString()) + "-------\nsdelta2: " + new String(sdelta2.toString()));

        intLengthBytes = c.getLengthInBytes() + T1.getLengthInBytes() + T2.getLengthInBytes() + T3.getLengthInBytes() + salpha.getLengthInBytes() + sbhta.getLengthInBytes() + sx.getLengthInBytes()
                + sdelta1.getLengthInBytes() + sdelta2.getLengthInBytes();

        // ************* DEBUG **********
//        System.out.println("------------Sign Length\n " + intLengthBytes + "\nc: " + c.getLengthInBytes() + "\nT1: " + T1.getLengthInBytes() + "\nT2: " + T2.getLengthInBytes() + "\nT3: "
//                + T3.getLengthInBytes() + "\nsa: " + salpha.getLengthInBytes() + "\nsb: " + sbhta.getLengthInBytes() + "\nsx: " + sx.getLengthInBytes() + "\nsd1: " + sdelta1.getLengthInBytes()
//                + "\nsd2: " + sdelta2.getLengthInBytes());
        // ************* DEBUG **********

        signature = new byte[intLengthBytes];

        offset = 0;
        System.arraycopy(T1.toBytes(), 0, signature, 0, T1.getLengthInBytes());
        offset += T1.getLengthInBytes();
        System.arraycopy(T2.toBytes(), 0, signature, offset, T2.getLengthInBytes());
        offset += T2.getLengthInBytes();
        System.arraycopy(T3.toBytes(), 0, signature, offset, T3.getLengthInBytes());
        offset += T3.getLengthInBytes();
        System.arraycopy(c.toBytes(), 0, signature, offset, c.getLengthInBytes());
        offset += c.getLengthInBytes();
        System.arraycopy(salpha.toBytes(), 0, signature, offset, salpha.getLengthInBytes());
        offset += salpha.getLengthInBytes();
        System.arraycopy(sbhta.toBytes(), 0, signature, offset, sbhta.getLengthInBytes());
        offset += sbhta.getLengthInBytes();
        System.arraycopy(sx.toBytes(), 0, signature, offset, sx.getLengthInBytes());
        offset += sx.getLengthInBytes();
        System.arraycopy(sdelta1.toBytes(), 0, signature, offset, sdelta1.getLengthInBytes());
        offset += sdelta1.getLengthInBytes();
        System.arraycopy(sdelta2.toBytes(), 0, signature, offset, sdelta2.getLengthInBytes());
        offset += sdelta2.getLengthInBytes();
//        System.arraycopy(myHash, 0, signature, offset, myHash.length);

        //System.out.println(offset);

        time_sign.add(timer_sign.getElapsedTime());
        
        //System.out.print("time to sign" + time_sign);
//        System.out.println("------------Sign Length\n " + intLengthBytes);
        return signature;

    }
}
