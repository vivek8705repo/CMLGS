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
import phases.Open;
import phases.SetUp;
import phases.Sign;
import phases.Verify;

/**
 *
 * @author V
 */
// BBS
public class GroupManager {

    private final static String ALGORITHM = "BBS";
    protected static HashMap<String, Element> GPK = new HashMap<String, Element>();
    protected static HashMap<String, Element>[] GSK = new HashMap[1000];
    protected static HashMap<String, Element> GMSK = new HashMap<String, Element>();
    protected static HashMap<String, Element> USERLIST = new HashMap<String, Element>();
    protected static byte[] signature;
    protected static Pairing thePairing;

    public GroupManager() {
    }

    @Test
    public void hello() {
   // public static void main(String[] args) {
        // set the value of number of members here
        int number_of_member[] = {100};
      
        // rBits and qBits define the security level of BBS scheme. In order to
        //set security level of 80 bits, value of rBits and qBits must be 170
        // and 171 bits respectively. 
         int rBits = 170;
        int[] qBits = {171};
        List<List<Long>> time_setup_final = new ArrayList<List<Long>>();
        List<List<Long>> time_sign_final = new ArrayList<List<Long>>();
        List<List<Long>> time_verify_final = new ArrayList<List<Long>>();
        List<List<Long>> time_open_final = new ArrayList<List<Long>>();
        List<List<Long>> key_length_final = new ArrayList<List<Long>>();
        List<List<Long>> sign_length_final = new ArrayList<List<Long>>();


  
        for (int q = 0; q < qBits.length; q++) {
            PairValue<Object, Object> pv = null;
            List<Long> key_length = new ArrayList<Long>();
            List<Long> time_setup = new ArrayList<Long>();
            List<Long> sign_length = new ArrayList<Long>();
            List<Long> time_sign = new ArrayList<Long>();
            List<Long> time_verify = new ArrayList<Long>();
            List<Long> time_open = new ArrayList<Long>();

    
            for (int i = 0; i < number_of_member.length; i++) {
                Stopwatch timer_setup = new Stopwatch().start();
                pv = SetUp.BBSGenerate(number_of_member[i], rBits, qBits[q]);
                time_setup.add(timer_setup.getElapsedTime());
                timer_setup.stop();
     
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
               
            }
            time_setup_final.add(time_setup);
//                Benchmark("D:\\result\\BBS\\set" + set_no + "\\" + "rBits " + "_" + rBits + "\\qBits_"
//                        + qBits[q] + "\\setup.txt", time_setup);
//
//                Benchmark("D:\\result\\BBS\\set" + set_no + "\\" + "rBits " + "_" + rBits + "\\qBits_"
//                        + qBits[q] + "\\Key_length.txt", key_length);
            key_length_final.add(key_length);
//
//            System.out.println("\nG1" + GPK.get("g1").getLengthInBytes()
//                    + "\nG2" + GPK.get("g2").getLengthInBytes() + "\nh" + GPK.get("h").getLengthInBytes()
//                    + "\nu" + GPK.get("u").getLengthInBytes() + "\nv" + GPK.get("v").getLengthInBytes()
//                    + "\nw" + GPK.get("w").getzLengthInBytes());

            String username = "User";
            for (int i = 1; i <= number_of_member[0]; i++) {
                USERLIST.put(username.concat(Integer.toString(i)), GSK[i - 1].get("A"));
            }

//                try {
//                    Benchmark("D:\\result\\BBS\\set" + set_no + "\\" + "rBits " + "_" + rBits + "\\qBits_"
//                            + qBits[q] + "\\userlist.txt", USERLIST);
//                } catch (IOException e) {
//                    System.out.println(e.getStackTrace());
//                }
            for (int set_no = 1; set_no < 10; set_no++) {                
     
                String msg = "There is an accident";

                sign_length = new ArrayList<Long>();
                time_sign = new ArrayList<Long>();
                time_verify = new ArrayList<Long>();
                time_open = new ArrayList<Long>();

                Stopwatch timer_sign = new Stopwatch().start();
                byte[] signature1 = Sign.BBSSign(thePairing, GPK, GSK[1], msg);
                time_sign.add(timer_sign.getElapsedTime());

                sign_length.add(Long.valueOf(signature1.length));

//                    Benchmark("D:\\result\\BBS\\set" + set_no + "\\" + "rBits " + "_" + rBits + "\\qBits_"
//                            + qBits[q] + "\\sign_length_bytes.txt", sign_length);
//
//                    Benchmark("D:\\result\\BBS\\set" + set_no + "\\" + "rBits " + "_" + rBits + "\\qBits_"
//                            + qBits[q] + "\\sign.txt", time_sign);

                Stopwatch timer_verify = new Stopwatch().start();
                boolean check = Verify.BBSVerify(thePairing, signature1, GPK, msg);
                time_verify.add(timer_verify.getElapsedTime());
//                    Benchmark("D:\\result\\BBS\\set" + set_no + "\\" + "rBits " + "_" + rBits + "\\qBits_"
//                            + qBits[q] + "\\verify.txt", time_verify);
                //System.out.println("\n Result for Verify:" + check);

                try {
                    Stopwatch timer_open = new Stopwatch().start();
                    Element A = Open.BBSOpen(thePairing, GPK, GMSK, signature1, "There is an accident");
                    time_open.add(timer_open.getElapsedTime());
//                        Benchmark("D:\\result\\BBS\\set" + set_no + "\\" + "rBits " + "_" + rBits + "\\qBits_"
//                                + qBits[q] + "\\open.txt", time_open);
                    for (int i = 1; i <= number_of_member[0]; i++) {
                        Element temp = USERLIST.get(username.concat(Integer.toString(i)));
                        if (A.isEqual(temp)) {
                           // System.out.println("Signature Opened Successfully, Signer is: "
                                   // + username.concat(Integer.toString(i)));
                        }
                    }
                } catch (Exception E) {
                    E.printStackTrace();
                }

                time_sign_final.add(time_sign);
                time_verify_final.add(time_verify);
                time_open_final.add(time_open);
                sign_length_final.add(sign_length);

                Benchmark1("D:\\result\\BBS\\" + rBits + "X" + qBits[q] + "\\key_length.txt", key_length_final);
                Benchmark1("D:\\result\\BBS\\" + rBits + "X" + qBits[q] + "\\sign_length.txt", sign_length_final);
                Benchmark1("D:\\result\\BBS\\" + rBits + "X" + qBits[q] + "\\set_up.txt", time_setup_final);
                Benchmark1("D:\\result\\BBS\\" + rBits + "X" + qBits[q] + "\\sign.txt", time_sign_final);
                Benchmark1("D:\\result\\BBS\\" + rBits + "X" + qBits[q] + "\\verify.txt", time_verify_final);
                Benchmark1("D:\\result\\BBS\\" + rBits + "X" + qBits[q] + "\\open.txt", time_open_final);

            }
//            time_sign_final.add(time_sign);
//            time_verify_final.add(time_verify);
//            time_open_final.add(time_open);
//            sign_length_final.add(sign_length);

            Benchmark1("D:\\result\\BBS\\" + rBits + "X" + qBits[q] + "\\key_length.txt", key_length_final);
            Benchmark1("D:\\result\\BBS\\" + rBits + "X" + qBits[q] + "\\sign_length.txt", sign_length_final);
            Benchmark1("D:\\result\\BBS\\" + rBits + "X" + qBits[q] + "\\set_up.txt", time_setup_final);
            Benchmark1("D:\\result\\BBS\\" + rBits + "X" + qBits[q] + "\\sign.txt", time_sign_final);
            Benchmark1("D:\\result\\BBS\\" + rBits + "X" + qBits[q] + "\\verify.txt", time_verify_final);
            Benchmark1("D:\\result\\BBS\\" + rBits + "X" + qBits[q] + "\\open.txt", time_open_final);

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

    public static void Benchmark1(String file, List<List<Long>> ls) {
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
