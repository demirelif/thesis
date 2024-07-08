package util.Hash;

import util.PSI.Parameters;

import java.math.BigInteger;
import java.util.ArrayList;

public class SimpleHash {
    Integer[][] hashTable;

    public SimpleHash(int length) {
        hashTable = new Integer[length][Parameters.BIN_CAPACITY];
    }

    public Integer[][] getHashTable() {
        return hashTable;
    }

    public boolean initializeHashTable(ArrayList<Integer> stream){
        int streamIndex = 0;
        try {
            for (int i = 0; i < hashTable.length; i++) {
                for (int j = 0; j < Parameters.BIN_CAPACITY; j++) {
                    if (streamIndex < stream.size()) {
                        hashTable[i][j] = stream.get(streamIndex);
                    } else {
                        hashTable[i][j] = (int) ((-1) * Math.random()); // Add dummy number
                    }
                    streamIndex++;
                }
            }
        } catch (Exception e){
            System.err.println("Hash table initialization failed");
            System.err.println(e.getMessage());
            return false;
        }
        return true;
    }

    public void printHashTable() {
        for (int i = 0; i < hashTable.length; i++) {
            System.out.print("Bin " + i + ": ");
            for (int j = 0; j < hashTable[i].length; j++) {
                System.out.print(hashTable[i][j] + " ");
            }
            System.out.println();
        }
    }
}
