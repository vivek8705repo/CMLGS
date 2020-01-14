/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package generic;

/**
 * This is a customized Exception class which is called when a received signature
 * in open phase is proved to be an invalid signature
 * @author Vivek Agrawal<vivek8705@gmail.com>
 */
public class MyException extends Exception {

    /**
     * This method returns a customized message in case of exception
     *  
     */
    @Override
    public String toString() {
        return ("Signature is invalid");
    }
}
