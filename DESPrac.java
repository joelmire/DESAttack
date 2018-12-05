import java.util.Random;
import java.io.*;
import java.math.BigInteger;
import java.util.HashSet;
import java.util.Iterator;
import java.lang.System;

class DESPrac {

    public static void main(String[] args) throws IOException {
    
        // Check that the 2-round DES implementation works correctly under a known plaintext, key, and ciphertext.
        long testP = 0x1234567887654321L;
        long testK = 0x33333333333333L;
        long testC = 0xC844E31B90953751L;
        
        System.out.print("DES implementation works: ");
        System.out.println(testDES(testP, testK, testC));
        
        // Time how long it takes to perform 1000 encryptions
        long start;
        long end;
        long dif;
        long C;
        
        start = System.nanoTime();
        for (int i = 0; i < 1000; i++) {
            C = callEncrypt(testP);
        }
        end = System.nanoTime();
        
        dif = end - start;
        System.out.print("Time required for 1000 encryptions (in nanoseconds): ");
        System.out.println(dif);
        
        //Time how long it takes (on average) to recover a 56-bit key using the exhaustion attack?
        
        /* 
        There are 2^56 possible keys. On average, an exhaustion will find the correct key half-way
        through this exhaustive search, that is, after 2^55 calls to the encrypt function. 
        1000 encryption takes approximately 1500000000 nanoseconds, or 1.5 seconds.
        We observe that ((1.5) / (1000)) = ((x) / (2^55)). 
        Then x = ((1.5)(2^55)) / (1000) seconds.
        x = 54043195528446 seconds, or 1713698 years.
        Another example is below:
        */
        
        BigInteger exhaustTime = new BigInteger(Long.toString(dif));
        // convert to seconds
        exhaustTime = exhaustTime.divide(new BigInteger("1000000000"));
        // multiply by 2^55
        exhaustTime = exhaustTime.multiply(new BigInteger("36028797018963968"));
        // divide by 1000
        exhaustTime = exhaustTime.divide(new BigInteger("1000"));
        // convert seconds to years
        exhaustTime = exhaustTime.divide(new BigInteger("31557600"));
        
        System.out.print("Estimated time required for an average exhaustion attack (in years): ");
        System.out.println(exhaustTime.toString());
        
        // Work on 1st SBox
        // Print differential distribution for SBox 1
        int SBox = 1;   
        differentialDistributionTable(SBox);
        
        // Find subkeyCandidates for the first subkey:
        // Use deltP with fixed difference 0x0080800260000000 (36169544707866624 in dec).
        // Use deltSBoxIn of 12 (0xC in hex) and deltSBoxOut of 13 (0xD in hex) based on the input-output results from the differential distribution table (14/64 probability).
        // Use characteristicCheck 0x0000000060000000 (1610612736 in dec).
        long deltP = 36169544707866624L;
        byte deltSBoxIn = 0xC;
        byte deltSBoxOut = 0xD;
        long characteristicCheck = 0x0000000060000000;

        HashSet<Byte> subkeyCandidates = new HashSet<>(reduceSubkey(SBox, deltP, deltSBoxIn, deltSBoxOut, characteristicCheck));
        
        
        // Work on 2nd SBox
        // Print differential distribution for SBox 2
        SBox = 2;
        differentialDistributionTable(SBox);
        
        /*
        deltP = 0x4000401002000000 (4611756455924596736 in dec).
        (deltL0, deltR0) = (0x40004010, 0x02000000)
        Applying the Round 1 E Box to deltR0: deltE1 = 0x004000000000
        Then the deltSBoxIn = 0x4
        From Table 2: deltSBoxOut = 0xC
        Then we have Round 1 delt0 = 0x0C000000
        Applying the P Box on Round 1 deltO: deltF1 = 0x40004010 with probability 12/64.
        Using the Feistel XOR, we have deltF1 ^ L0 = deltR1 = 0x00000000
        Thus, L2 = 0x00000000 and R2 = 0x02000000.
        */
        System.out.printf("0x%08x\n", PBox(0x07000000));
        //System.out.println(0x40004010 ^ 0x00080010);
        
        // Find subkeyCandidates for the first subkey:
        // Use deltP with fixed difference 0x4000401002000000 (4611756455924596736 in dec).
        // Use deltSBoxIn of 4 (0x4 in hex) and deltSBoxOut of 7 (0x7 in hex) based on the input-output results from the differential distribution table (12/64 probability).
        // Use characteristicCheck __________________ (_____________ in dec).
        deltP = 4611756455924596736L;
        deltSBoxIn = 0x4;
        deltSBoxOut = 0x7;
        characteristicCheck = 0x0000000002000000; 
        subkeyCandidates = new HashSet<>(reduceSubkey(SBox, deltP, deltSBoxIn, deltSBoxOut, characteristicCheck));
        System.out.println(subkeyCandidates.size());
        
    }


    static void differentialDistributionTable (int SBox) {
    
        /* 
        Task 2 Question i: Explain why the output of every S box is uniformly distributed
        if the input is uniformly distributed.
        
        "Given a 6-bit input, the 4-bit output is found by selecting the row using the outer two bits 
        (the first and last bits), and the column using the inner four bits. For example, 
        an input "011011" has outer bits "01" and inner bits "1101"; the corresponding output would be "1001"" (Wikipedia). 
        */
        
        byte[] sTable = STables[SBox - 1];
        // initalize 2d array that will be used to map 64 possible S to 16 possible deltS differentials.
        byte[][] difDistTable = new byte[64][16];
        int sPrime;
        int deltO;
        
        // Map 64 possible S to 16 possible deltS differentials.
        // 64 possible deltS where deltS = S ^ S' 
        for (int i = 0; i < 64; i++) {
            // 64 possible S
            for (int j = 0; j < 64; j++) {
            	// S' = S ^ deltS
            	sPrime = j ^ i;
            	// deltO = O ^ O' where O and O' are found in the given S box's lookup table with indices S and S', respectively.
            	deltO = sTable[i] ^ sTable[sPrime];
            	// update the frequency table
            	difDistTable[j][deltO]++;
            }
        }
        
        // Print the differential distribution table.
        System.out.printf("   ");
        for (int i = 0; i < 16; i++) {
            System.out.printf("%3d",i);
        }
        System.out.println();
        System.out.println("----------------------------------------------------");
        for (int i = 0; i < 64; i++) {
            System.out.printf("%3d:",i);
            for (int j = 0; j < 16; j++) {
                System.out.printf("%3d",difDistTable[i][j]);
            }
            System.out.println();
        }
    }
    
    
    static HashSet<Byte> reduceSubkey(int SBox, long deltP, byte deltSBoxIn, byte deltSBoxOut, long characteristicCheck) throws IOException {
    
        // initialize keyspace
        HashSet<Byte> keyspace = new HashSet<>();
        for (int i = 0; i < 64; i++) {
            keyspace.add((byte) i);
        }
        
        // initialize pseudo-random number generator
        Random prng = new Random();		
        
        long P;
        long P_;
        long deltC;
        long E;
        long ESub;
        long R0;
        
        // Initialize set of possible keys
        HashSet<Integer> PI = new HashSet<>();
        byte[] sTable = STables[SBox - 1];
        int sPrime;
        int deltO;
        
        // 64 possible S
        for (int s = 0; s < 64; s++) {
            // S' = S ^ deltS
            sPrime = s ^ deltSBoxIn;
            // deltO = O ^ O' where O and O' are found in the given S box's lookup table with indices S and S', respectively.
            deltO = sTable[s] ^ sTable[sPrime];
            if (deltO == deltSBoxOut) {		
            	  PI.add(s);
            	}
        }        

        while (keyspace.size() > 2) {
        
            P = prng.nextLong();
            P_ = P ^ deltP;
            deltC = callEncrypt(P) ^ callEncrypt(P_);

            if (deltC == characteristicCheck) {
                // determine E
                R0 = P&MASK32;
                E = EBox(R0);
                // isolate relevant bits of E by shifting to remove irrelevant lower order bits and then masking irrelevant higher order bits.
                ESub = (E >> (48 - 6 * SBox)) & MASK6;

                for (int key : keyspace) {
                    if (!PI.contains((int) ESub ^ key)) {	
                        keyspace.remove((byte) key);
                    }
                }
            }    
        }
        
        return keyspace;
    }


    // constants for &-ing with, to mask off everything but the bottom 32- or 48-bits of a long
    static long MASK32 = 0xffffffffL;
    static long MASK48 = 0xffffffffffffL;
    static long MASK6 = 0x3fL;


    static long TwoRoundModifiedDES(long K, long P) { // input is a 56-bit key "long" and a 64-bit plaintext "long", returns the ciphertext

        long L0=(P>>32)&MASK32; // watch out for the sign extension!
        long R0=P&MASK32;
        long K1=K&MASK48;
        long K2=(K>>8)&MASK48;

        long L1=R0;
        long R1=L0^Feistel(R0, K1);

        long L2=R1;
        long R2=L1^Feistel(R1, K2);

        long C=L2<<32 | R2;

        return(C);
    }

    static long Feistel(long R, long K) { // input is a 32-bit integer and 48-bit key, both stored in 64-bit signed "long"s; returns the output of the Feistel round

        long F;
        
        // E box
        F = EBox(R);
        // XOR with subkey
        F = F ^ K;
        // S boxes
        F = SBox(F);
        // P box
        F = PBox(F);
        // XOR with lower 32 bits of subkey
        F = F ^ (K&MASK32);

        return(F);
    }

    // NB: these differ from the tables in the DES standard because the latter are encoded in a strange order

    static final byte[] S1Table={
     3,  7,  5,  1, 12,  8,  2, 11, 10,  3, 15,  6,  7, 12,  8,  2,
    13,  0, 11,  4,  6,  5,  1, 14,  0, 10,  4, 13,  9, 15, 14,  9,
     4,  1,  2, 12, 11, 14, 15,  5, 14,  7,  8,  3,  1,  8,  5,  6,
     9, 15, 12, 10,  0, 11, 10,  0, 13,  4,  7,  9,  6,  2,  3, 11,
    };

    static final byte[] S2Table={
    13,  1,  2, 15,  8, 13,  4,  8,  6, 10, 15,  3, 11,  7,  1,  4,
    10, 12,  9,  5,  3,  6, 14, 11,  5,  0,  0, 14, 12,  9,  7,  2,
     7,  2, 11,  1,  4, 14,  1,  7,  9,  4, 12, 10, 14,  8,  2, 13,
     0, 15,  6, 12, 10,  9, 13,  0, 15,  3,  3,  5,  5,  6,  8, 11,
    };

    static final byte[] S3Table={
    14,  0,  4, 15, 13,  7,  1,  4,  2, 14, 15,  2, 11, 13,  8,  1,
     3, 10, 10,  6,  6, 12, 12, 11,  5,  9,  9,  5,  0,  3,  7,  8,
     4, 15,  1, 12, 14,  8,  8,  2, 13,  4,  6,  9,  2,  1, 11,  7,
    15,  5, 12, 11,  9,  3,  7, 14,  3, 10, 10,  0,  5,  6,  0, 13,
    };

    static final byte[] S4Table={
    10, 13,  0,  7,  9,  0, 14,  9,  6,  3,  3,  4, 15,  6,  5, 10,
     1,  2, 13,  8, 12,  5,  7, 14, 11, 12,  4, 11,  2, 15,  8,  1,
    13,  1,  6, 10,  4, 13,  9,  0,  8,  6, 15,  9,  3,  8,  0,  7,
    11,  4,  1, 15,  2, 14, 12,  3,  5, 11, 10,  5, 14,  2,  7, 12,
    };

    static final byte[] S5Table={
     7, 13, 13,  8, 14, 11,  3,  5,  0,  6,  6, 15,  9,  0, 10,  3,
     1,  4,  2,  7,  8,  2,  5, 12, 11,  1, 12, 10,  4, 14, 15,  9,
    10,  3,  6, 15,  9,  0,  0,  6, 12, 10, 11,  1,  7, 13, 13,  8,
    15,  9,  1,  4,  3,  5, 14, 11,  5, 12,  2,  7,  8,  2,  4, 14,
    };

    static final byte[] S6Table={
     2, 14, 12, 11,  4,  2,  1, 12,  7,  4, 10,  7, 11, 13,  6,  1,
     8,  5,  5,  0,  3, 15, 15, 10, 13,  3,  0,  9, 14,  8,  9,  6,
     4, 11,  2,  8,  1, 12, 11,  7, 10,  1, 13, 14,  7,  2,  8, 13,
    15,  6,  9, 15, 12,  0,  5,  9,  6, 10,  3,  4,  0,  5, 14,  3,
    };

    static final byte[] S7Table={
    12, 10,  1, 15, 10,  4, 15,  2,  9,  7,  2, 12,  6,  9,  8,  5,
     0,  6, 13,  1,  3, 13,  4, 14, 14,  0,  7, 11,  5,  3, 11,  8,
     9,  4, 14,  3, 15,  2,  5, 12,  2,  9,  8,  5, 12, 15,  3, 10,
     7, 11,  0, 14,  4,  1, 10,  7,  1,  6, 13,  0, 11,  8,  6, 13,
    };

    static final byte[] S8Table={
     4, 13, 11,  0,  2, 11, 14,  7, 15,  4,  0,  9,  8,  1, 13, 10,
     3, 14, 12,  3,  9,  5,  7, 12,  5,  2, 10, 15,  6,  8,  1,  6,
     1,  6,  4, 11, 11, 13, 13,  8, 12,  1,  3,  4,  7, 10, 14,  7,
    10,  9, 15,  5,  6,  0,  8, 15,  0, 14,  5,  2,  9,  3,  2, 12,
    };


    // STables[i-1][s] is the output for input s to S-box i
    static final byte[][] STables={S1Table, S2Table, S3Table, S4Table, S5Table, S6Table, S7Table, S8Table};


    static long SBox(long S) { // input is a 48-bit integer stored in 64-bit signed "long"

        // Split I into eight 6-bit chunks
        int Sa=(int)((S>>42));
        int Sb=(int)((S>>36)&63);
        int Sc=(int)((S>>30)&63);
        int Sd=(int)((S>>24)&63);
        int Se=(int)((S>>18)&63);
        int Sf=(int)((S>>12)&63);
        int Sg=(int)((S>>6)&63);
        int Sh=(int)(S&63);
        // Apply the S-boxes
        byte Oa=S1Table[Sa];
        byte Ob=S2Table[Sb];
        byte Oc=S3Table[Sc];
        byte Od=S4Table[Sd];
        byte Oe=S5Table[Se];
        byte Of=S6Table[Sf];
        byte Og=S7Table[Sg];
        byte Oh=S8Table[Sh];
        // Combine answers into 32-bit output stored in 64-bit signed "long"
        long O=(long)Oa<<28 | (long)Ob<<24 | (long)Oc<<20 | (long)Od<<16 | (long)Oe<<12 | (long)Of<<8 | (long)Og<<4 | (long)Oh;
        return(O);
    }


    static long EBox(long R) { // input is a 32-bit integer stored in 64-bit signed "long"

        // compute each 6-bit component
        long Ea=(R>>27)&31 | (R&1)<<5;
        long Eb=(R>>23)&63;
        long Ec=(R>>19)&63;
        long Ed=(R>>15)&63;
        long Ee=(R>>11)&63;
        long Ef=(R>>7)&63;
        long Eg=(R>>3)&63;
        long Eh=(R>>31)&1 | (R&31)<<1;
        // 48-bit output stored in 64-bit signed "long"
        long E=(long)Ea<<42 | (long)Eb<<36 | (long)Ec<<30 | (long)Ed<<24 | (long)Ee<<18 | (long)Ef<<12 | (long)Eg<<6 | (long)Eh;
        return(E);
    }

    static final int[] Pbits={
    16,  7, 20, 21,
    29, 12, 28, 17,
     1, 15, 23, 26,
     5, 18, 31, 10,
     2,  8, 24, 14,
    32, 27,  3,  9,
    19, 13, 30,  6,
    22, 11,  4, 25
    };

    // this would have been a lot faster as fixed binary operations rather than a loop
    static long PBox(long O) { // input is a 32-bit integer stored in 64-bit signed "long"

        long P=0L;
        for(int i=0; i<32; i++)
        {
            P|=((O>>(32-Pbits[i]))&1) << (31-i);
        }
        return(P);
    }
    
    // a helper method to test the DES implementation using a known plaintext and key
    static boolean testDES(long testP, long testK, long testC) {
        long C;
        C = TwoRoundModifiedDES(testK, testP);
        return (C == testC);
    }

    // a helper method to call the external programme "desencrypt" in the current directory
    // the parameter is the 64-bit plaintext to encrypt, returns the ciphertext
    static long callEncrypt(long P) throws IOException {

        Process process = Runtime.getRuntime().exec("./desencrypt "+Long.toHexString(P));
        String CString = (new BufferedReader(new InputStreamReader(process.getInputStream()))).readLine();

        // we have to go via BigInteger otherwise the signed longs cause incorrect parsing
        long C=new BigInteger(CString, 16).longValue();

        return(C);
    }

}