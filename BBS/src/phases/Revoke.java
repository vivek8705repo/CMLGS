/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package phases;

import generic.Stopwatch;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;

/**
 * This class is used by BBS scheme to implement revocation feature in the group
 * GM publishes the revocation list |RL|  which contains private key of the 
 * revoked users. Using the values present in |RL|, anyone can compute group 
 * public key to verify signatures and all unrevoked vehicles can update their 
 * key by re-computing a part of their previous private key
@author Vivek Agrawal<vivek.agrawal@harman.com>
 */
public class Revoke {

    protected static HashMap<String, Element> GPK_NEW = new HashMap<String, Element>();
    protected static HashMap<String, Element>[] GSK_NEW = new HashMap[1000];

    /**
     * 
     * @param thePairing The Pairing interface provides the methods to access the
     * algebraic structures (G1, G2, GT, Zr) involved in the pairing computation
     * @param GPK  The public key of group
     * @param gamma A random element
     * @param USERLIST List of the member in the group
     * @param user The revoked user of the group
     * @param xi private key of the revoked member
     */
    public static void memberRevoke(Pairing thePairing, HashMap<String, Element> GPK,
            Element gamma, HashMap<String, Element> USERLIST, String user, Element xi) {

        Element Pair_A_g2 = thePairing.getGT().newElement();
        Element g1_new = thePairing.getG1().newRandomElement();
        g1_new = GPK.get("g1").powZn(xi.add(gamma).invert()).getImmutable();

        Element g2_new = thePairing.getG1().newRandomElement();
        g2_new = GPK.get("g2").powZn(xi.add(gamma).invert()).getImmutable();

        Element w_new = g2_new.powZn(gamma).getImmutable();

        Set set = USERLIST.entrySet();
        // Get an iterator
        Iterator i = set.iterator();
        int count = 0;
        while (i.hasNext()) {
            Map.Entry me = (Map.Entry) i.next();
            if (!me.getKey().equals(user)) {
                Stopwatch check= new Stopwatch().start();
                Element x = USERLIST.get((String) me.getKey());
                Element A_new = g1_new.powZn(x.add(gamma).invert()).getImmutable();
                int sum= x.getLengthInBytes()+ A_new.getLengthInBytes();
               // System.out.println("size of RL:" + sum );
                long cert= check.getElapsedTime();
                //System.out.println("time to calculate new value :" + cert);
                
                GSK_NEW[count] = new HashMap<String, Element>();
                GSK_NEW[count].put("A", A_new);
                GSK_NEW[count].put("x", x);

                Pair_A_g2 = thePairing.pairing(GSK_NEW[count].get("A"), GPK.get("g2"));
                GSK_NEW[count].put("pair_A_g2", Pair_A_g2.getImmutable());
                ++count;
            }
        }
        GPK_NEW.put("g1", g1_new);
        GPK_NEW.put("g2", g2_new);
        GPK_NEW.put("h", (Element) GPK.get("h"));
        GPK_NEW.put("u", (Element) GPK.get("u"));
        GPK_NEW.put("v", (Element) GPK.get("v"));
        GPK_NEW.put("w", w_new);
    }
}
