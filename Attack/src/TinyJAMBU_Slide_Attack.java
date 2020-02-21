import java.util.ArrayList;
import java.util.HashMap;
import java.util.Random;


/**
 *
 * TinyJAMBU reduced sliding attack demonstration code
 * Very similar parameters/ process compared to CLX, reduced by factor of 7
 *      18 bit state
 *      18 bit key
 *      4 bit message blocks
 *      2^8 online calls
 *      16 bit security goal
 *      feedback = s0 ⊕ s6 ⊕ (∼ (s8&s11)) ⊕ s13 ⊕ ki mod klen
 */


public class TinyJAMBU_Slide_Attack {


    /**
     * @param State : Current state
     * @param key : Key used for the update
     * @return : Updated state with one round
     */
    public static long Round(long State, long key)
    {

        State = State ^ (5L << 2); // Add FrameBits (2..4)
        State = P_fast(State,146, key); // original is 1024, now one seventh rounded
        return State;
    }


    /**
     * @param State : Current state
     * @param m : Message to add to state
     * @param key : Key used for update
     * @return : Updated state
     */
    public static long Round(long State, Long m, long key)
    {

        State = Round(State, key);
        State = State ^ (m<<14); // XOR s{14...17} with message of 4 bit
        return State;
    }



    /**
     * Reference permutation implementation, nround specify direction of permutation and number of steps to perform
     * @param State : Current state
     * @param nround : If positive, perform nround steps. If negative, perform -nround inversed steps
     * @param key : Key used for update
     * @return updated state
     */
    public  static  long P(long State, int nround, long key)
    {

        if(nround>=0)
        {
            for(int t = 0;t < nround;t++)
            {
                long Feedback = (((State>>0)) ^ ((State>>6)) ^ ~(  ((State>>8)) & ((State>>11))  ) ^ ((State>>13)) ^ (key >> t % 18) )& 1l; // feedback bit
                State = Feedback << 17 | (State>>1)  ;
            }
        }
        else
        {
            for(int t = 0;t <-nround;t++)
            {
                long Feedbackinv = (((State>>17)) ^ ((State>>5)) ^ ~(  ((State>>7) ) & ((State>>10) ) ) ^ ((State>>12) ^ (key << t % 18) ))& 1l;
                State = ((State<<1)  | Feedbackinv)& 0x3FFFFL;
            }
        }
        return State;
    }


    /**
     * Fast permutation implementation, 3 steps at a time, nround specify direction of permutation and number of steps to perform
     * @param State : Current state
     * @param nround : If positive, perform nround steps. If negative, perform -nround inversed steps
     * @param key : Key used for update
     * @return updated state
     */
    public  static  long P_fast(long State, int nround, long key)
    {
        for(int t = 0; t<nround/3 ;t++)
        {
            long Feedback = (((State>>0)) ^ ((State>>6)) ^ ~(  ((State>>8)) & ((State>>11))  ) ^ ((State>>13)) ^ (key >> t * 3 % 18) ) & 7L;
            State = Feedback << 15 | (State>>3)  ;


        }
        return State;

    }



    /**
     * @param S : Bit vector to print
     */
    public static void printbit(long S)
    {
        for(int t=0;t<18;t++)
        {
            System.out.print(""+ (S&01l));
            S = S >>1;
        }
        System.out.println();

    }


    /**
     * Function to demonstrate attack on TinyJAMBU reduced
     * @param args
     */
    public static void main(String[] args)
    {

        long key = 191662L; // arbitrary key
        long T0 = 0L; // initial state 0

        HashMap<Long, ArrayList<Long>> OnlineVs = new HashMap<>(); // HashMap used to find collision
        int SHIFTABS = 1;// Number of slides to test. 0 for standard collision test, 1 or more for sliding attack
        System.out.println("SHIFTABS : " +SHIFTABS);
        double tic = System.currentTimeMillis();
        long Nit = 1L << 8; // 2^8, max ciphered block call amount
        long preV = 0;
        long m = 14; // arbitrary message

        // Online iterations
        for(long t=0;t<Nit;t++)
        {
            m = (m + t)%15 + 1;// pseudo random message, used to generate various state during online operation
            T0 = Round(T0,m,key);


            long V = (T0 >> 14)^m; // Recover the visible internal state, xor with message to recover the known state bits
            long Q = (preV<<4) + V; // Key stored in the HashMap, with current visible bits and previous visible bits.

            ADDSTATES(Q, (T0 ^(m<<14)), OnlineVs,SHIFTABS, key);

            preV = V^m;
        }

        Random rand = new Random();
        Random rand2 = new Random();
        long key2 = 0L;
        long statecollision = 0;
        m = 88;
        long Nit2 = 1L << 32; // 2^32, offline call amount
        long ncoll = 0;
        long ngoodcoll = 0;
        preV = 0;
        T0 = 0L;

        // Offline iterations
        for(long t=0;t<Nit2;t++)
        {
            m = rand2.nextInt(15)+1;//another pseudo random message, used to generate various state during online operation
            T0 = Round(T0,m,key2);

            long V = (T0 >> 14)^m;// Recover the visible internal state , xor with message to recover the known state bits
            long Q = (preV<<4) + V;// Key stored in the hashmap, with current visible bits and previous visible bits.


            if( OnlineVs.containsKey(Q))// Check for collision with online keys
            {
                ncoll += OnlineVs.get(Q).size();// Update number of candidate collision counter
                for(long S : OnlineVs.get(Q))
                {
                    if(S == (T0 ^(m<<14))) // Check if the online state is the same as the offline state (in practice, this would require some ciphering step, simplified here).
                    {
                        statecollision++;
                        if ((key2) == (key)) // check if random key is the same as online key
                        {
                            ngoodcoll++;// Increase number of valid collisions
                            System.out.println("x");
                        }
                    }
                }
            }

            key2 = rand.nextInt(1 << 18); // generate new pseudorandom key

            if(t%10000000 == 0){
                System.out.print(".");
            }

            preV = V^m;

        }

        // Log results
        System.out.println("\n" + "NKeys : " + OnlineVs.size());
        System.out.println("State collided amount : " + statecollision);
        System.out.println("Ncollisions mes : " + ncoll);
        System.out.println("Ncollisions exp : " + (1L << 16)); //2^16 bit security goal
        System.out.println("goodcoll mes : " + ngoodcoll);




        double toc = System.currentTimeMillis();
        System.out.println("time : " + (toc-tic) + " ms");
        System.out.println("Iterations per second : " + (long)((Nit2)/(toc-tic)) + " kit/s");
        printbit(T0);

    }




    /**
     * Store in the hashmap the reached state pair. Also store the slided versions of the pairs
     * @param Q Currect state
     * @param T0
     * @param OnlineVs
     * @param SHIFTABS
     * @param key
     */
    public static void ADDSTATES(long Q, long T0,HashMap<Long, ArrayList<Long>> OnlineVs, int SHIFTABS, long key)
    {

        int MINSHIFT = -SHIFTABS;
        int MAXSHIFT =  SHIFTABS;


        // Shift is the slide value
        for(int shift = MINSHIFT; shift <= MAXSHIFT;shift++)
        {

            long TP = P(T0,-shift, key);// The state used to generate current state

            // Generate all candidate states using padding for the undefined bits
            for(long PADL = 0; PADL < (1L <<Math.abs(shift)); PADL++)

            {
                for(long PADM = 0; PADM < (1L <<Math.abs(shift)); PADM++)
                {

                    long M = Q>>4;
                    long L = Q & 0xFL;

                    // Padd the M and L values
                    if(shift>=0)
                    {
                        M = ((M << shift) + PADM)& 0xFL;
                        L = ((L << shift) + PADL)& 0xFL;
                    }else
                    {
                        M = (M >> (-shift)) + (PADM<<(4+shift));
                        L = (L >> (-shift)) + (PADL<<(4+shift));
                    }

                    long Qt = (M<<4) + L; // Generate the associated Key value containing current state and the state after one round with sliding and padding

                    if( OnlineVs.containsKey(Qt))  // if hashmap contains the associated key value
                    {
                        OnlineVs.get(Qt).add(TP);  // add that state (TP) to the key
                    }
                    else
                    {
                        // create an arraylist, add TP, add new hashmap entry
                        ArrayList<Long > A = new ArrayList<Long>();
                        A.add(TP);
                        OnlineVs.put(Qt,A);
                    }
                }
            }

        }


    }
}


