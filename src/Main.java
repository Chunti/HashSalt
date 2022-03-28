import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.sql.*;
import java.util.Arrays;
import java.util.Scanner;


public class Main {

    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeySpecException {

    }

    public void hashSalt(String password) throws InvalidKeySpecException, NoSuchAlgorithmException {
        Scanner scanner = new Scanner(System.in);
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[16];
        random.nextBytes(salt);

        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt , 65536, 128);

        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");

        byte[] hash = factory.generateSecret(spec).getEncoded();

        saveHashSalt(hash,salt);
    }


    private void saveHashSalt(String email, byte[] hashSalt, byte[] salt) throws DatabaseException {
        String sql = "insert into `data` (EMail, Hash, Salt) values (?,?,?)";
        try (Connection connection = database.connect()) {
            try (PreparedStatement ps = connection.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS )) {
                ps.setString(1,email);
                ps.setBytes(2, hashSalt);
                ps.setBytes(3, salt);
                ps.executeUpdate();
            } catch (SQLException throwables) {
                throw new DatabaseException("Could not insert user and ");
            }
        } catch (SQLException | DatabaseException ex) {
            ex.printStackTrace();
            throw new DatabaseException("Could not establish connection to database");
        }
    }


    public void checkPassword(String email, String password) throws DatabaseException, NoSuchAlgorithmException, InvalidKeySpecException, InterruptedException {

        String sql =  "SELECT * FROM hashsalttest.data where EMail = ?;";
        byte[] hash = new byte[0];
        byte[] salt = new byte[0];

        try (Connection connection = database.connect()) {
            try (PreparedStatement ps = connection.prepareStatement(sql)) {
                ps.setString(1, email);
                ResultSet rs = ps.executeQuery();
                if (rs.next()) {
                    hash = rs.getBytes("Hash");
                    salt = rs.getBytes("Salt");
                } else {
                    throw new DatabaseException("Couldn't find that email");
                }
            } catch (SQLException ex) {
                throw new DatabaseException("Couldn't find that email");
            } catch (DatabaseException e) {
                e.printStackTrace();
            }
        } catch (SQLException ex) {
            throw new DatabaseException("Could not establish connection to database");
        }

        KeySpec check = new PBEKeySpec(password.toCharArray(),salt,65536,128);
        SecretKeyFactory factory1 = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");

        byte[] userPassword = factory1.generateSecret(check).getEncoded();
        if(Arrays.equals(hash,userPassword)){
            System.out.println("KODEORDET ER ENS!");
        }
    }

    private static String toHex(byte[] array) {
        BigInteger bi = new BigInteger(1, array);
        String hex = bi.toString(16);

        int paddingLength = (array.length * 2) - hex.length();
        if(paddingLength > 0)
        {
            return String.format("%0"  +paddingLength + "d", 0) + hex;
        }else{
            return hex;
        }
    }
}
