/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */


import generic.PairValue;
import generic.Stopwatch;
import it.unisa.dia.gas.jpbc.Element;
import java.util.HashMap;
import it.unisa.dia.gas.jpbc.Pairing;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import org.junit.Test;
import phases.SetUp;
import phases.Sign;


/**
 *
 * @author V
 */
public class Message_Sign_length {

    private final static String ALGORITHM = "BBS";
    protected static HashMap<String, Element> GPK = new HashMap<String, Element>();
    protected static HashMap<String, Element>[] GSK = new HashMap[1000];
    protected static HashMap<String, Element> GMSK = new HashMap<String, Element>();
    protected static HashMap<String, Element> USERLIST = new HashMap<String, Element>();
    protected static byte[] signature;
    protected static Pairing thePairing;
   

    @Test
    public void hello() {
        int n = 10;
        int rBits = 170;
        int[] qBits = {171};

        List<List<Long>> sign_length_final = new ArrayList<List<Long>>();
        for (int q = 0; q < qBits.length; q++) {
            PairValue<Object, Object> pv = null;
            List<Long> time_sign = new ArrayList<Long>();
         
                pv = SetUp.BBSGenerate(n, rBits, qBits[q]);
                PairValue<HashMap, HashMap> kp = (PairValue) pv.getA();
                PairValue<HashMap[], Pairing> pv2 = (PairValue) pv.getB();

                GPK = kp.getA();
                GMSK = kp.getB();
                GSK = pv2.getA();
                thePairing = pv2.getB();          

            String username = "User";
            for (int i = 1; i <= n; i++) {
                USERLIST.put(username.concat(Integer.toString(i)), GSK[i - 1].get("A"));
            }

            for (int set_no = 1; set_no < 10; set_no++) {
                List<Long> sign_length = new ArrayList<Long>();
                for (int count = 1; count <= 10; count = count * 2) {
                    try {
                        SecureRandom random = new SecureRandom();
                        BigInteger b = new BigInteger(count, random);
                        String msg = b.toString();
                        Stopwatch timer_sign = new Stopwatch().start();
                        byte[] signature1 = Sign.BBSSign(thePairing, GPK, GSK[5], msg);
                        time_sign.add(timer_sign.getElapsedTime());
                        sign_length.add(Long.valueOf(signature1.length));
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                }
                sign_length_final.add(sign_length);
            }
        }
        Benchmark1("D:\\result\\BBS\\Message_sign_length.txt", sign_length_final);
    }

    public void Benchmark1(String file, List<List<Long>> ls) {
        try {
            File f = new File(file);
            f.getParentFile().mkdirs();
            FileWriter writer = new FileWriter(f);
            BufferedWriter bufferedWriter = new BufferedWriter(writer);
            for (List<Long> temp : ls) {
                for (long q : temp) {
                    bufferedWriter.write(Long.toString(q));
                    bufferedWriter.write("\t");
                }
                bufferedWriter.newLine();
            }
            bufferedWriter.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
