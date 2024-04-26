import java.util.Scanner;
import java.io.File;
import java.io.FileNotFoundException;
/**
 * an implementation of the Advanced Encryption Standard (AES) algorithm
 *
 * Author : Farhad Mirzapour
 */
public class AES
{
    //sbox array that is going to be used in the encryption
    private static long sbox[][] = {
            //0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
            {0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76},
            {0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0},
            {0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15},
            {0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75},
            {0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84},
            {0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf},
            {0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8},
            {0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2},
            {0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73},
            {0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb},
            {0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79},
            {0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08},
            {0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a},
            {0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e},
            {0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf},
            {0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16} 
        };
    //inverse sbox array that is going to be used in the decryption
    private static long  invsbox[][] = {
            {0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb},
            {0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb},
            {0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e},
            {0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25},
            {0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92},
            {0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84},
            {0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06},
            {0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b},
            {0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73},
            {0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e},
            {0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b},
            {0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4},
            {0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f},
            {0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef},
            {0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61},
            {0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d } 
        };

    // an array of length 10 containing 64 bit constant values that are used in the expand routine
    private static long C_arr[] = {
            0x01000000,
            0x02000000, 0x04000000,
            0x08000000, 0x10000000,
            0x20000000, 0x40000000,
            0x80000000, 0x1B000000,
            0x36000000
        };
    private static String keyData = "";
    /* Name :main
     * input parameter: String[] args which are the arguments supplied to the program by the user, indicating the name of the 2 text files corresponding to the plaintext and key values
     * output paramter: 
     * description: encrypts the given plaintext according to the given key and decrypt its back (using appopriate subroutines),
     * printing important results of the process including the ciphertext.

     */
    public static void main(String[] args){

        String plaintextFileName = args[0];
        String keyFileName = args[1];
        String plaintextData= "";

        try { // opens the files and reads the key and plaintext
            File plaintextFile = new File(plaintextFileName);
            File keyFile = new File(keyFileName);
            Scanner reader = new Scanner(plaintextFile);
            plaintextData = reader.nextLine();

            reader.close();
            Scanner reader2 = new Scanner(keyFile);
            keyData = reader2.nextLine();
            reader2.close();

        } catch (FileNotFoundException e) {
            System.out.println("An error occurred in opening the files.");
            e.printStackTrace();
        }
        
        // formats the key text by padding with 0s
        String [] tempArr = keyData.split(" ");
        String tempStr = "";
        for (int i=0;i<tempArr.length;i++) {
            if (tempArr[i].length()!=2) {
                tempStr+="0";
                tempStr+=tempArr[i];
            }
            else {
                tempStr+=tempArr[i];
            }
            tempStr+=" ";

        }
        keyData = tempStr;
        
        // formats the plain text by padding with 0s
        tempArr = plaintextData.split(" ");
        tempStr = "";
        for (int i=0;i<tempArr.length;i++) {
            if (tempArr[i].length()!=2) {
                tempStr+="0";
                tempStr+=tempArr[i];
            }
            else {
                tempStr+=tempArr[i];
            }
            tempStr+=" ";

        }
        plaintextData = tempStr;
        System.out.println("PlAINTEXT");
        System.out.println(plaintextData);
        System.out.println("KEY");
        System.out.println(keyData);
        System.out.println("KEY SCHEDULE:");
        long [] [] keys = expand(); // call to the expand function that gives us the key schedule
        for (int i = 0 ; i <11; i ++) {
            for (int j = 0 ; j < 4 ; j++) {
                System.out.print(Long.toHexString(keys[i][j])+" ");
            }
            System.out.println();
        }
        System.out.println();
        System.out.println("ENCRYPTION PROCESS");
        System.out.println("-------");
        System.out.println("PlAINTEXT");
        System.out.println(plaintextData);
        long [][]cipherArr = encrypt(plaintextData); // encrypt subroutine returns cipherArr which contains the ciphertext
        System.out.println("CIPHERTEXT:");
        String ciphertext = "";
        for (int p =0 ; p <4 ;p++) { //cipher text is extracted from cipherArr
            for (int q =0 ; q <4 ;q++) {
                
                ciphertext+= (Long.toHexString(cipherArr[q][p]) + " ");
            }

        }
        // formats the cipher text by padding with 0s
        tempArr = ciphertext.split(" ");
        tempStr = "";
        for (int i=0;i<tempArr.length;i++) {
            if (tempArr[i].length()!=2) {
                tempStr+="0";
                tempStr+=tempArr[i];
            }
            else {
                tempStr+=tempArr[i];
            }
            tempStr+= " ";

        }
        ciphertext = tempStr;
        
        System.out.println();
        System.out.println(ciphertext);
        System.out.println();
        System.out.println("DECRYPTION PROCESS");
        System.out.println("-------");
        System.out.println("CIPHERTEXT:");
        
       
        System.out.println(ciphertext);
        long [][]PlainArr = decrypt(ciphertext); // calls the decrypt function with the ciphertext which gives the plaintext in the plainArr 2d array
        System.out.println("PLAINTEXT");
        
        // printing and extracting the plaintext back from plainArr
        for (int p =0 ; p <4 ;p++) {
            for (int q =0 ; q <4 ;q++) {
                
                System.out.print(Long.toHexString(PlainArr[q][p]) + " ");
            }

        }
        System.out.println();
        
        System.out.println("END OF PROCESSING");

    }

    /* Name :subbytes
     * input parameter: long [][] inputArr which is the 2d state array whose entries are to be replaced
     * output paramter: long [][] outputArr which is the 2d state array whose entries are correctly replaced
     * description: important method that is used in the routine of AES, entries of the state array are replaced using the sbox matrix

     */
    public static long [][] subbytes(long [][] inputArr){
        long [][] outputArr = new long [inputArr.length] [inputArr[0].length]; 
        for (int i =0 ; i<inputArr.length ; i ++) {
            for (int j =0 ; j<inputArr[0].length ; j ++) {
                outputArr[i][j] = sbox[(int) inputArr[i][j]/16]  [(int) inputArr[i][j]%16];
            }
        }
        return outputArr;
    }

    /* Name :shiftrows
     * input parameter: long [][] inputArr which is the 2d state array whose rows are to be shifted
     * output paramter: long [][] outputArr which is the inputArr after the rows are correctly shifted
     * description: important method that is used in the routine of AES (mainly encryption) , each row i of the state matrix is cyclicly shifted to the left by i

     */
    public static long [][] shiftrows(long [][] inputArr){
        long [][] outputArr = new long [4] [4]; 
        for (int i =0 ; i<4 ; i ++) {
            for (int j =0 ; j<4 ; j ++) {
                outputArr[i][j] = inputArr[i][ (j+i) % 4];
            }
        }
        return outputArr;
    }

    /* Name :expand
     * input parameter: String keyData which is the key read from the file specified from the user
     * output paramter: long [][] outputArr which is the 11 by 4 2d array of keys that is going to be used in the AES encryption and decyrption
     * description: important method that is used in the routine of AES, uses subbytes and cyclic shift to construct keys that are going to be used in the AES routine

     */
    public static long [][] expand(){
        long [][] outputArr = new long [11][4];

        keyData = keyData.replace(" ","");

        outputArr[0][0] = Long.parseLong(keyData.substring(0,8),16);
        outputArr[0][1] = Long.parseLong(keyData.substring(8,16),16);
        outputArr[0][2] = Long.parseLong(keyData.substring(16,24),16);
        outputArr[0][3] = Long.parseLong(keyData.substring(24,32),16);
        for ( int i = 1 ; i <=10 ; i++ ) {
            outputArr[i][0] = negativeCheck(outputArr[i-1][0] ^ expand_stateToHex(subbytes (expand_hexToState(expand_cyclicShift(outputArr[i-1][3]) )) ) ^ C_arr[i-1]);
            outputArr[i][1] = negativeCheck(outputArr[i-1][1] ^ outputArr[i][0]);
            outputArr[i][2] = negativeCheck(outputArr[i-1][2] ^ outputArr[i][1]);
            outputArr[i][3] = negativeCheck(outputArr[i-1][3] ^ outputArr[i][2]);

        }
        return outputArr;
    }

    /* Name :negativeCheck
     * input parameter: long in which is an integer that is going to be checked
     * output paramter: long out which is the correct integer representation of long in
     * description: helper method for expand that circles the two's complement problem of long values after they are incremented and turned negative

     */
    public static long negativeCheck (long in){
        String hexstr = Long.toHexString(in);
        if (hexstr.length() >=8) {
            if (hexstr.substring(0,8).equals("ffffffff")) { // avoid negative long values
                return Long.parseLong(hexstr.substring(8,hexstr.length()),16);
            }
        }
        return Long.parseLong(hexstr,16);

    }

    /* Name :expand_hexToState
     * input parameter: long hexvalue which is a long integer that is going to be turned into a state array
     * output paramter: long [][] outputArr which is a state array representation of long hexvalue
     * description: helper method for expand that turns a hex value into a 4 by 1 state arr

     */
    public static long [][] expand_hexToState(long hexvalue){
        long [][] outputArr = new long [4][1];
        for (int i = 0 ; i<4;i++ ) { // seperates the 2 hex characters and adds them to outputArr
            long twobits = hexvalue >> ((3-i) * 8);
            outputArr[i][0] = twobits;
            hexvalue = hexvalue - (     twobits << ((3-i) * 8)    );
        }

        return outputArr;
    }

    /* Name :expand_stateToHex
     * input parameter: long [][] state which is a state array that is to be turned into a long integer
     * output paramter: the long value corresponding to the state array long state[][]
     * description: helper method for expand that turns a 4 by 1 state array into a hex value

     */
    public static long expand_stateToHex(long [][] state){
        long out = 0;
        for (int i = 0 ; i<4;i++ ) { // the hex characters are added at the correct positions to output number long out
            out+= state[i][0] << ((3-i) * 8); 
        }
        return out;
    }

    /* Name :expand_cyclicShift
     * input parameter: long hexvalue which is a long integer that is supposed to be cyclicly shifted
     * output paramter: long hexvalue after it is cyclicly shifted
     * description: helper method for expand that takes a long value and cyclicly shifts it to the right by 8

     */
    public static long expand_cyclicShift(long hexvalue){

        long twoLeftHex  = hexvalue >> 24; // the two left most hex characters of hexvalue
        hexvalue -= (twoLeftHex << 24 ); // two left most hex chars are removed
        hexvalue = hexvalue << 8; // shifted to the right by 2 hex chars
        hexvalue += twoLeftHex; // the two left most are added on the right most side
        return hexvalue;
    }

    /* Name :gf256_02 
     * input parameter: long a which is to be multiplied by 02
     * output paramter: result of the multiplication
     * description: helper method for mixcolumns routine that returns the result of multiplying an 8 bit long number by 02 in GF(256)

     */
    public static long gf256_02 (long a) {

        if ( ((a>>7) ^ 1) == 0) { // if the bit being shifted out is a 1
            return (a<<1) ^ 27 ^ 256;
        }

        return a<<1;

    }

   

    // the following are helper methods that do specific multiplications in gf(256) and are used as helper methods in inverse_mixcolumn subroutine
    public static long gf256_03 (long a) {

        return ( (gf256_02(a)) ^ (a)  );

    }
    public static long gf256_0b (long a) {

        return ( (gf256_02(a)) ^ (a) ^ gf256_02(gf256_02(gf256_02(a))));

    }

    public static long gf256_09 (long a) {

        return (  (a) ^ gf256_02(gf256_02(gf256_02(a))));

    }

    public static long gf256_0e (long a) {

        return (   gf256_02(gf256_02(gf256_02(a))) ^  gf256_02(gf256_02(a)) ^  (gf256_02(a) ) );

    }

    public static long gf256_0d (long a) {
        return (   gf256_02(gf256_02(gf256_02(a))) ^  gf256_02(gf256_02(a)) ^  a ) ;
    }

    /* Name :encryption_matrix_mult_gf256
     * input parameter: long[][] state which is a 4 by 1 state "vector" to be multiplied by the needed mix cols matrix
     * output paramter: long[][] out result of the multiplication
     * description: helper method for mixcolumns routine that returns the result of multiplying a 4 by 1 state "vector" by the appropriate matrix
     */
    public static long[] encryption_matrix_mult_gf256 (long[] state) {
        long[] out = new long[4];
        out[0] = gf256_02(state[0]) ^ gf256_03(state[1]) ^ state[2] ^ state[3] ;
        out[1] = state[0] ^ gf256_02(state[1]) ^ gf256_03(state[2]) ^ state[3] ;
        out[2] = state[0] ^ state[1] ^ gf256_02(state[2]) ^ gf256_03(state[3]) ;
        out[3] = gf256_03(state[0]) ^ state[1] ^ state[2] ^ gf256_02(state[3]) ;
        return out;

    }
    /* Name :mixcolumns
     * input parameter: long[][] state which is the state array
     * output paramter: long[][] out result of the mixing of culumn
     * description: important subroutine used in the encryption of AES which mixes columns according to multiplication in gf 256
     */
    public static long[][] mixcolumns (long[][] state) {

        long[][] out = new long[4][4];
        for (int i = 0 ; i < 4 ; i ++ ) {
            for (int j = 0; j<4 ; j++) {
                out[j][i] = encryption_matrix_mult_gf256(longToVector(vectorToLong(state,i)))[j];
            }
        }
        return out;
    }

    /* Name :longToVector
     * input parameter: long hexvalue which is a long integer that is going to be turned into a state array
     * output paramter: long [] outputArr which is a state array representation of long hexvalue
     * description: 

     */
    public static long [] longToVector(long hexvalue){
        long [] outputArr = new long [4];
        for (int i = 0 ; i<4;i++ ) { // seperates the 2 hex characters and adds them to outputArr
            long twobits = hexvalue >> ((3-i) * 8);
            outputArr[i] = twobits;
            hexvalue = hexvalue - (     twobits << ((3-i) * 8)    );
        }

        return outputArr;
    }
/* Name :vectorTolong
     * input parameter: long state which is the state array and int col which is the desired column of the state array
     * output paramter: long out which is the long representation of the specified column
     * description: represented the specified column of the state array as a long

     */
    public static long vectorToLong(long [][] state, int col){
        long out = 0;
        for (int i = 0 ; i<4;i++ ) { 
            out+= state[i][col] << ((3-i) * 8); 
        }
        return out;
    }
/* Name :transpose
     * input parameter: long [][] a which is the 2d array that is going to be transposed
     * output paramter: long transposed which is the transpose of a
     * description: tranposes the input 2d array a and returns it

     */
    public static long[][] transpose(long[][] a){

        long[][] transposed = new long[a[0].length][a.length];
        for(int i = 0; i < a[0].length; i++) {
            for(int j = 0; j < a.length; j++) {
                transposed[i][j] = a[j][i];
            }
        }

        return transposed;
    }
/* Name :encrypt
     * input parameter: string plaintext
     * output paramter: long[][] out which is the state array containing the ciphertext
     * description: encrypt the plaintext and prints out important information along the processs

     */
    public static long[][] encrypt (String plaintext) {    

        long [][] keys = expand();

        plaintext = plaintext.replace(" ","");
        long [][]s = {
                longToVector(Long.parseLong(plaintext.substring(0,8),16) ^ keys[0][0]),
                longToVector(Long.parseLong(plaintext.substring(8,16),16) ^ keys[0][1]),
                longToVector(Long.parseLong(plaintext.substring(16,24),16) ^ keys[0][2]),
                longToVector(Long.parseLong(plaintext.substring(24,32),16) ^ keys[0][3])
            };
        s=transpose(s);

        for (int i =1 ; i <11 ;i++) {
            s= subbytes(s);

            s=shiftrows(s);

            if (i<=9) {
                s=mixcolumns(s);
                //printing the result of mixcolumns
                System.out.println("State after call "+i+" to MixColumns()");
                System.out.println("---------------------------------------------");
                for (int p =0 ; p <4 ;p++) {
                    for (int q =0 ; q <4 ;q++) {
                        System.out.print(Long.toHexString(s[q][p]) + " ");
                    }

                }
                System.out.println();
            }

            for (int j =0 ; j <4 ;j++) {
                long[]  vec  = longToVector((vectorToLong(s,j) ^ keys[i][j]) );
                for (int l  = 0 ; l <4; l++ ) {
                    s[l][j] = vec[l];
                }
            }

        }

        
        return s;
    }

    /* Name :inverse_subbytes
     * input parameter: long [][] inputArr which is the 2d state array whose entries are to be replaced
     * output paramter: long [][] outputArr which is the 2d state array whose entries are correctly replaced
     * description: important method that is used in the decryption routine of AES, entries of the state array are replaced using the inverse sbox matrix

     */
    public static long [][] inverse_subbytes(long [][] inputArr){
        long [][] outputArr = new long [inputArr.length] [inputArr[0].length]; 
        for (int i =0 ; i<inputArr.length ; i ++) {
            for (int j =0 ; j<inputArr[0].length ; j ++) {
                outputArr[i][j] = invsbox[(int) inputArr[i][j]/16]  [(int) inputArr[i][j]%16];
            }
        }
        return outputArr;
    }

    /* Name : inverse_shiftrows
     * input parameter: long [][] inputArr which is the 2d state array whose rows are to be shifted
     * output paramter: long [][] outputArr which is the inputArr after the rows are correctly shifted
     * description: important method that is used in the decryption routine of AES , each row i of the state matrix is cyclicly shifted to the right by i

     */
    public static long [][] inverse_shiftrows(long [][] inputArr){
        long [][] outputArr = new long [4] [4]; 
        for (int i =0 ; i<4 ; i ++) {
            for (int j =0 ; j<4 ; j ++) {
                outputArr[i][j] = inputArr[i][ (4+(j-i)) % 4];
            }
        }
        return outputArr;
    }

    /* Name :decryption_matrix_mult_gf256
     * input parameter: long[][] state which is a 4 by 1 state "vector" to be multiplied by the needed mix cols matrix
     * output paramter: long[][] out result of the multiplication
     * description: helper method for inverse_mixcolumns routine that returns the result of multiplying a 4 by 1 state "vector" by the appropriate matrix
     */
    public static long[] decryption_matrix_mult_gf256 (long[] state) {
        long[] out = new long[4];
        out[0] = gf256_0e(state[0]) ^ gf256_0b(state[1]) ^ gf256_0d(state[2]) ^ gf256_09(state[3]) ;
        out[1] = gf256_09(state[0]) ^ gf256_0e(state[1]) ^ gf256_0b(state[2]) ^ gf256_0d(state[3]) ;
        out[2] = gf256_0d(state[0]) ^ gf256_09(state[1]) ^ gf256_0e(state[2]) ^ gf256_0b(state[3]) ;
        out[3] = gf256_0b(state[0]) ^ gf256_0d(state[1]) ^ gf256_09(state[2]) ^ gf256_0e(state[3]) ;
        return out;

    }
    /* Name :inverse_mixcolumns
     * input parameter: long[][] state which is the state array whose columns will be inverse mixed
     * output paramter: long[][] out which is the state array after the column are inverse mixed
     * description: importanted subroutine that inverse mixes the columns of the state array according to calculations in gf256 and acts as helper to decrypt

     */
    public static long[][] inverse_mixcolumns (long[][] state) {

        long[][] out = new long[4][4];
        for (int i = 0 ; i < 4 ; i ++ ) {
            for (int j = 0; j<4 ; j++) {
                out[j][i] = decryption_matrix_mult_gf256(longToVector(vectorToLong(state,i)))[j];
            }
        }
        return out;
    }
/* Name :decrypt
     * input parameter: string ciphertext
     * output paramter: long[][] out which is the state array containing the plaintext
     * description: decrypt the ciphertext and prints out important information along the processs

     */
    public static long[][] decrypt (String ciphertext) {
        long [][] keys = expand();

        ciphertext = ciphertext.replace(" ","");
        long [][]s = {
                longToVector(Long.parseLong(ciphertext.substring(0,8),16) ),
                longToVector(Long.parseLong(ciphertext.substring(8,16),16) ),
                longToVector(Long.parseLong(ciphertext.substring(16,24),16) ),
                longToVector(Long.parseLong(ciphertext.substring(24,32),16))
            };
        s=transpose(s);
        for (int i =10 ; i >=1 ;i--) {

            for (int j =0 ; j <4 ;j++) {
                long[]  vec  = longToVector((vectorToLong(s,j) ^ keys[i][j]) );
                for (int l  = 0 ; l <4; l++ ) {
                    s[l][j] = vec[l];
                }
            }

            if (i<=9) {
                s=inverse_mixcolumns(s);
                //printing the result of inverse mixcolumns
                System.out.println("State after call "+(10-i)+" to inverse MixColumns()");
                System.out.println("---------------------------------------------");
                for (int p =0 ; p <4 ;p++) {
                    for (int q =0 ; q <4 ;q++) {
                        System.out.print(Long.toHexString(s[q][p]) + " ");
                    }

                }
                System.out.println();
            }
            s=inverse_shiftrows(s);
            s= inverse_subbytes(s);

            


        }
        for (int j =0 ; j <4 ;j++) {
            long[]  vec  = longToVector((vectorToLong(s,j) ^ keys[0][j]) );
            for (int l  = 0 ; l <4; l++ ) {
                s[l][j] = vec[l];
            }
        }
        return s;

    }

}
