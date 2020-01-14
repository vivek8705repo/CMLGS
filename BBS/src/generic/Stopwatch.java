/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package generic;

/**
 * A class to help benchmark code
 * It simulates a real stop watch
 *  @author Vivek Agrawal<vivek8705@gmail.com>
 */
public class Stopwatch {

    private long startTime = -1;
    private long stopTime = -1;
    private boolean running = false;

    /**
     * To initialize value of startTime as the current system time
     * 
     */
    public Stopwatch start() {
        startTime = System.currentTimeMillis();
        running = true;
        return this;
    }

    /**
     * To initialize value of stopTime as the current system time
     * 
     */
    public Stopwatch stop() {
        stopTime = System.currentTimeMillis();
        running = false;
        return this;
    }

    /** returns elapsed time in milliseconds
     * if the watch has never been started then
     * return zero
     */
    public long getElapsedTime() {
        if (startTime == -1) {
            return 0;
        }
        if (running) {
            return System.currentTimeMillis() - startTime;
        } else {
            return stopTime - startTime;
        }
    }

    /**
     * 
     * To reset the stopwatch
     */
    public Stopwatch reset() {
        startTime = -1;
        stopTime = -1;
        running = false;
        return this;
    }
}
