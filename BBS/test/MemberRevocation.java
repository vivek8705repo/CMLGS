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
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.util.ArrayList;
import java.util.List;
import org.junit.Test;
import phases.Revoke;
import phases.SetUp;


/**
 * 
 * @author Vivek Agrawal<vivek8705@gmail.com>
 */
public class MemberRevocation {

    private final static String ALGORITHM = "BBS";
    protected static HashMap<String, Element> GPK = new HashMap<String, Element>();
    protected static HashMap<String, Element>[] GSK = new HashMap[1000];
    protected static HashMap<String, Element> GMSK = new HashMap<String, Element>();
    protected static HashMap<String, Element> USERLIST = new HashMap<String, Element>();
    protected static byte[] signature;
    protected static Pairing thePairing;

    @Test
    public void hello() {
        int number_of_member[] = {100};

        int rBits = 170;
        int qBits = 171;
        List<List<Long>> time_revoke_final = new ArrayList<List<Long>>();


        PairValue<Object, Object> pv = null;

        List<Long> key_length = new ArrayList<Long>();
        
       

        for (int i = 0; i < number_of_member.length; i++) {

            List<Long> time_revoke = new ArrayList<Long>();
            pv = SetUp.BBSGenerate(number_of_member[i], rBits, qBits);

            PairValue<HashMap, HashMap> kp = (PairValue) pv.getA();
            PairValue<HashMap[], Pairing> pv2 = (PairValue) pv.getB();

            GPK = kp.getA();

            key_length.add(Long.valueOf(GPK.get("g1").getLengthInBytes()
                    + GPK.get("g2").getLengthInBytes() + GPK.get("h").getLengthInBytes()
                    + GPK.get("u").getLengthInBytes() + GPK.get("v").getLengthInBytes()
                    + GPK.get("w").getLengthInBytes()) * 8);
            GMSK = kp.getB();
            GSK = pv2.getA();
            thePairing = pv2.getB();
            Element gamma = SetUp.getGamma();

            String username = "User";
            for (int count = 1; count <= number_of_member[i]; count++) {
                USERLIST.put(username.concat(Integer.toString(count)), GSK[count - 1].get("x"));
            }

           // System.out.println("revocation size:"
                  //  + (GSK[1].get("x").getLengthInBytes() + GSK[1].get("A").getLengthInBytes()));
            for (int set_no = 1; set_no < 100; set_no++) {
                // revoke phase starts

                Element xi = USERLIST.get("User6");
                Stopwatch timer_revoke = new Stopwatch().start();
                Revoke.memberRevoke(thePairing, GPK, gamma, USERLIST, "User6", xi);
                time_revoke.add(timer_revoke.getElapsedTime());

            }
            time_revoke_final.add(time_revoke);
        

            Benchmark1("D:\\result\\BBS\\Revoke\\" + rBits + "X" + qBits + "\\revoke.txt", time_revoke_final);


        }
    }

    public static void Benchmark(String file, List<Long> ls) {
        try {
            File f = new File(file);
            f.getParentFile().mkdirs();
            FileWriter writer = new FileWriter(f);
            BufferedWriter bufferedWriter = new BufferedWriter(writer);
            for (long temp : ls) {
                bufferedWriter.write(Long.toString(temp));
                bufferedWriter.newLine();
            }
            bufferedWriter.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
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

    public void Benchmark(String file, HashMap<String, Element> table) throws IOException {
        File f = new File(file);
        f.getParentFile().mkdirs();
        FileOutputStream fo = new FileOutputStream(f);
        OutputStreamWriter out = new OutputStreamWriter(fo);
        String eol = System.getProperty("line.separator");
        for (String key : table.keySet()) {
            out.write("\"");
            out.write(key);
            out.write("\",\"");
            out.write(String.valueOf(table.get(key)));
            out.write("\"");
            out.write(eol);
        }
        out.flush();

    }
}
