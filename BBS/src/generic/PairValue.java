/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package generic;

/**
 * This class is used to create object of a pair value. 
 * <p> This class is called and used wherever there is a requirement to return
 * more than one value from a function
 * @author Vivek Agrawal<vivek8705@gmail.com>
 * @param <A> Any data type and value
 * @param <B> Any data type value
 */
public class PairValue <A, B> {
    
    public final A a;
    public final B b;
    
    public PairValue(A a, B b){
        this.a=a;
        this.b=b;
    }
    
    public A getA(){
        return a;
    }
    public B getB(){
        return b;
    }
}
