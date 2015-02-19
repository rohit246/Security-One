/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package core;
import java.util.*;

/**
 *
 * @author Rohit
 */
public class MaliciousDecisionEngine {
    
    public static boolean DecideMaliciousness(double probability)
    {
        if(probability == 0.0)
        {
            return false;
        }
        Random rng = new Random();
        final int randomNumber = rng.nextInt(100);
        return randomNumber <= (100*probability) ? true : false;
    }
}
