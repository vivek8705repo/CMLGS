/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package phases;

import generic.PairValue;
import it.unisa.dia.gas.jpbc.CurveGenerator;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.CurveParams;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.pairing.a.TypeACurveGenerator;
import java.io.InputStream;
import java.security.KeyPair;
import java.util.HashMap;

/**
 * This class is responsible to generate Group Public key (gpk) and Group Secret
 * Key (gsk). This class must only be accessed by the Group Manager of a Group. 
 * @author Vivek Agrawal<vivek.agrawal@harman.com>
 */
public class SetUp {

    protected static HashMap<String, Element> GPK = new HashMap<String, Element>();
    protected static HashMap<String, Element>[] GSK = new HashMap[1000];
    protected static HashMap<String, Element> GMSK = new HashMap<String, Element>();
    protected static byte[] signature;
    protected static byte[] rsaSignatureBuf;
    protected static Pairing thePairing;
    protected static KeyPair keys;
    public static Element gamma;

    /**
     * 
     * @param n number of Members in the group
     * @param rBits Minimum bits of prime subgroup
     * @param qBits minimum bits of big field
     * @see  http://eprint.iacr.org/2005/076.pdf
     * @see http://gas.dia.unisa.it/projects/jpbc/docs/curvegenerator.html#TypeA
     * @return A PairValue of (group public key, group secret key) and (member 
     * private key , the pairing computation (G1,G2,GT,Zr))
     */
    public static PairValue BBSGenerate(int n, int rBits, int qBits) {



        // curve and pairing initialisation 
        InputStream in = null;
        CurveGenerator curveGenerator = new TypeACurveGenerator(rBits,
                qBits);
        CurveParams curveParams = (CurveParams) curveGenerator.generate();

        thePairing = PairingFactory.getPairing(curveParams);


        /*
         * Select a generator g2 in G2 uniformly at random, and set g1<-psi(g2)
         */
        Element g1 = thePairing.getG1().newRandomElement().getImmutable();
        Element g2 = thePairing.getG2().newRandomElement().getImmutable();
        Element h = thePairing.getG1().newRandomElement().getImmutable();

        /*
         * ksi1 and ksi2 are random number from Multiplicative group of integers modulo p
         */
        Element ksi1 = thePairing.getZr().newRandomElement().getImmutable();
        Element ksi2 = thePairing.getZr().newRandomElement().getImmutable();
        gamma = thePairing.getZr().newRandomElement().getImmutable();

        Element Pair_h_g2 = thePairing.getGT().newElement();
        Element Pair_A_g2 = thePairing.getGT().newElement();
        Element Pair_h_w = thePairing.getGT().newElement();

        GPK.put("g1", g1);
        GPK.put("g2", g2);
        GPK.put("h", h);

        Element u = h.powZn(ksi1.invert());
        GPK.put("u", u.getImmutable());

        Element v = h.powZn(ksi2.invert());
        GPK.put("v", v.getImmutable());
        Element w = g2.powZn(gamma);
        GPK.put("w", w.getImmutable());

        //Private key of Group Manager
        GMSK.put("§1", ksi1);
        GMSK.put("§2", ksi2);

        Pair_h_g2 = thePairing.pairing(GPK.get("h"), GPK.get("g2"));
        Pair_h_w = thePairing.pairing(GPK.get("h"), GPK.get("w"));


        GPK.put("pair_h_g2", Pair_h_g2.getImmutable());
        GPK.put("pair_h_w", Pair_h_w.getImmutable());

        //creation of private key for all group members
        for (int i = 0; i < n; i++) {
            Element x = thePairing.getZr().newRandomElement().getImmutable();
            Element tmp = x.add(gamma);
            tmp.invert();
            Element A = g1.powZn(tmp);

            GSK[i] = new HashMap<String, Element>();
            GSK[i].put("A", A.getImmutable());
            GSK[i].put("x", x);

            Pair_A_g2 = thePairing.pairing(GSK[i].get("A"), GPK.get("g2"));
            GSK[i].put("pair_A_g2", Pair_A_g2.getImmutable());

        }
        PairValue kp = new PairValue(GPK, GMSK);
        PairValue pv = new PairValue(GSK, thePairing);
        return new PairValue(kp, pv);
    }
    
    public static Element getGamma(){
        return gamma;
    }
}
