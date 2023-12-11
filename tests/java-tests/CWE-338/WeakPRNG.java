import java.io.File;
import java.io.FileNotFoundException;
import java.util.Random;
import java.util.Scanner;

public class WeakPRNG {
    public static void main(String[] args) {
        File file = new File("input.txt");
        try {
            Scanner scanner = new Scanner(file);
            while (scanner.hasNextLine()) {
                String line = scanner.nextLine();
                int randomNumber = generateRandomNumber(line);
                int randomNumberWithEntropy = generateRandomNumberWithEntropy(line);
                System.out.println(line + " " + randomNumber + " " + randomNumberWithEntropy);
            }
            scanner.close();
        } catch (FileNotFoundException e) {
            System.out.println("File not found.");
        }
    }

    private static int generateRandomNumber(String line) {
        int seed = line.hashCode();
        Random random = new Random(seed);
        int randomNumber = random.nextInt();
        return randomNumber;
    }

    private static int generateRandomNumberWithEntropy(String line) {
        double randomDouble = Math.random();
        int randomNumberWithEntropy = (int) (randomDouble * 100);
        return randomNumberWithEntropy;
    }
}