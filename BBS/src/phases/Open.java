/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package phases;


import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import java.util.HashMap;
import generic.MyException;

/**
 * This class can be accessed only by the group Manager to reveal identity of the
 * message signer
@author Vivek Agrawal<vivek.agrawal@harman.com>
 */
public class Open {

    /**
     * 
     * @param thePairing The Pairing interface provides the methods to access the
     * algebraic structures (G1, G2, GT, Zr) involved in the pairing computation.
     * @param GPK The public key of group
     * @param GMSK The secret key of group
     * @param signature This is the group Signature which will be opened in this 
     * method
     * @param msg The message which is used to generate the signature
     * @return UserId of the signer
     * @throws MyException If a wrong signature is received to be opened then this
     * Exception will be thrown
     */
    public static Element BBSOpen(Pairing thePairing, HashMap<String, Element> GPK, HashMap<String, Element> GMSK, byte[] signature, String msg) throws MyException {
        Element A = null;
        try {
            boolean check = Verify.BBSVerify(thePairing, signature, GPK, msg);
            if (check == false) {
                throw new MyException();
            } else {
                Element T1 = thePairing.getG1().newElement();
                Element T2 = thePairing.getG1().newElement();
                Element T3 = thePairing.getG1().newElement();
                Element salpha = thePairing.getZr().newElement();
                Element sbhta = thePairing.getZr().newElement();
                Element sx = thePairing.getZr().newElement();
                Element sdelta1 = thePairing.getZr().newElement();
                Element sdelta2 = thePairing.getZr().newElement();
                Element c = thePairing.getZr().newElement();
                Element M = thePairing.getG1().newElement();

                int pointerInSignature = T1.setFromBytes(signature, 0);
                pointerInSignature += T2.setFromBytes(signature, pointerInSignature);
                pointerInSignature += T3.setFromBytes(signature, pointerInSignature);
                pointerInSignature += c.setFromBytes(signature, pointerInSignature);
                pointerInSignature += salpha.setFromBytes(signature, pointerInSignature);
                pointerInSignature += sbhta.setFromBytes(signature, pointerInSignature);
                pointerInSignature += sx.setFromBytes(signature, pointerInSignature);
                pointerInSignature += sdelta1.setFromBytes(signature, pointerInSignature);
                pointerInSignature += sdelta2.setFromBytes(signature, pointerInSignature);
                M.setFromHash(signature, pointerInSignature, signature.length - pointerInSignature);


                T1 = T1.getImmutable();
                T2 = T2.getImmutable();
                T3 = T3.getImmutable();

                Element ks1 = GMSK.get("§1");
                Element ks2 = GMSK.get("§2");

                A = T3.div(T1.powZn(ks1).mul(T2.powZn(ks2))).getImmutable();

            }
        } catch (MyException e) {
            System.out.println(e);
        }
        return A;
    }
}
