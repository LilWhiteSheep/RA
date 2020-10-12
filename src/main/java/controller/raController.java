package controller;


import crypto.AES;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.util.encoders.Hex;
import org.springframework.context.annotation.Scope;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.*;
import java.sql.*;
import java.util.Map;

@RestController
@RequestMapping("/ra")
@Scope(value = "prototype")
public class raController
{
    //crypto
    AES aes = new AES();

    static String pkOfTaInStr = "03e4c54770e81f33975d64d5814f3360811b59252fc98f76d4b94229a5ac0cbcea";
    static String skOfTaInStr = "00eeaaf4991f597d7d1427f552f4c5a4aab582659883f6c1929ead7267933da27f";
    static String pkOfRaInStr = "03be262515cc6b491a19f53ab136d33924b20d81228e72788a0078e36fcaceaf2c";
    static String skOfRaInStr = "00af68a0fe9d64ca56f7f22876171537cff8741ad8d805ee924d9002e970633032";

    KeyPair publicKeyOfTa;
    KeyPair privateKeyOfRa;

    {
        try
        {
            publicKeyOfTa = new KeyPair(ecdsaString2Pk(pkOfTaInStr), ecdsaString2Sk(skOfTaInStr));
            privateKeyOfRa = new KeyPair(ecdsaString2Pk(pkOfRaInStr), ecdsaString2Sk(skOfRaInStr));
        } catch (Exception e)
        {
            e.printStackTrace();
        }
    }
    @RequestMapping(value = "/disclosure/{params}", method = RequestMethod.POST)
    public String disclosure(@PathVariable String params) throws NoSuchAlgorithmException, SignatureException, NoSuchProviderException, InvalidKeyException, UnsupportedEncodingException
//    public Map<String, String> disclosure(@PathVariable String params)
    {
        byte[] secret = Hex.decode("47e6cdd021889547777871f760f6327d079853e69ef7b93760b80391e6c36af4");
        BigInteger iv = new BigInteger("43641381315881849743323381336905490715");
        // m = seed-gid
        //1.收到disclosure需求  -->enc(k, {m-sig}
        System.out.println("receive disclosure request from TA");
        //2.解密然後確認ECDSA sig
        aes.createKey(secret, iv);
        byte[] cipher = Hex.decode(params);
        String disclosure_message = new String(aes.decrypt(cipher));
        String[] split_disclosure_message = disclosure_message.split("-");
        String disclosureSeed = split_disclosure_message[0];
        String disclosureGid = split_disclosure_message[1];
        String ecdsaSig = split_disclosure_message[2];
        if(validateSignature(disclosureSeed + "-" + disclosureGid, publicKeyOfTa , Hex.decode(ecdsaSig)))
        {
            System.out.println("validate success");
        //3.從資料庫中找到此seed相對應的vid
            String disclosureVid = getCorrespondVid(disclosureGid, disclosureSeed);
        //4.generate correspond sig
            String respondSig = Hex.toHexString(generateEcdsaSignature(disclosureVid, privateKeyOfRa));
            byte[] respondindCipher = aes.encrypt(concatenateByteArray((disclosure_message + "-").getBytes(), respondSig.getBytes()));
            return Hex.toHexString(respondindCipher);
        }

        //4.generate correspond sig
        //5.respond
        return null;
    }

    @RequestMapping(value = "/createtableRegist/{params}", method = RequestMethod.POST)
    public Map<String, String> createtable(@PathVariable String params)
    {
        createTableRegist(params);
        System.out.println("create table " + params + " done");
        return null;
    }


    public static byte[] concatenateByteArray(byte[] a, byte[] b)
    {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        try
        {
            outputStream.write(a);
            outputStream.write(b);

            return outputStream.toByteArray();
        } catch (IOException e)
        {
            e.printStackTrace();
        }

        return null;
    }

    static boolean validateSignature(String plaintext, KeyPair keyPair, byte[] sig) throws NoSuchProviderException, NoSuchAlgorithmException, InvalidKeyException, UnsupportedEncodingException, SignatureException
    {
        Signature ecdsaVerify = Signature.getInstance("SHA256withECDSA", "BC");
        ecdsaVerify.initVerify(keyPair.getPublic());
        ecdsaVerify.update(plaintext.getBytes());
        return ecdsaVerify.verify(sig);
    }

    public static PublicKey ecdsaString2Pk(String pk) throws Exception
    {
		/*KeyFactory kf = KeyFactory.getInstance("ECDH", "BC");
		return kf.generatePublic(new X509EncodedKeySpec(data));*/

        Provider BC = new BouncyCastleProvider();
        ECParameterSpec params = ECNamedCurveTable.getParameterSpec("secp256k1");
        ECPublicKeySpec pubKey = new ECPublicKeySpec(params.getCurve().decodePoint(Hex.decode(pk)), params);
        KeyFactory kf = KeyFactory.getInstance("ECDSA", BC);
        return kf.generatePublic(pubKey);
    }

    public static PrivateKey ecdsaString2Sk(String sk) throws Exception
    {
		/*KeyFactory kf = KeyFactory.getInstance("ECDH", "BC");
		return kf.generatePublic(new X509EncodedKeySpec(data));*/
        Provider BC = new BouncyCastleProvider();
        ECParameterSpec params = ECNamedCurveTable.getParameterSpec("secp256k1");
        ECPrivateKeySpec priKey = new ECPrivateKeySpec(new BigInteger(Hex.decode(sk)), params);
        KeyFactory kf = KeyFactory.getInstance("ECDSA", BC);
        return kf.generatePrivate(priKey);
    }

    static byte[] generateEcdsaSignature(String plainText, KeyPair keyPair) throws SignatureException, UnsupportedEncodingException, InvalidKeyException, NoSuchProviderException, NoSuchAlgorithmException
    {
        Signature ecdsaSign = Signature.getInstance("SHA256withECDSA", "BC");
        ecdsaSign.initSign(keyPair.getPrivate());
        ecdsaSign.update(plainText.getBytes("UTF-8"));
        byte[] signature = ecdsaSign.sign();
        System.out.println(signature.toString());
        return signature;
    }

    public static String getCorrespondVid(String group_id, String seed)
    {
        String disclosureVid = null;
        System.out.println(seed);
        Connection connection = null;
//        Statement statement = null;
        PreparedStatement preparedStatement = null;
        try
        {
            Class.forName("org.sqlite.JDBC");
            connection = DriverManager.getConnection("jdbc:sqlite:RA.db");
            connection.setAutoCommit(false);
            System.out.println("open database successfully");
//            statement = connection.createStatement();


            String sql = "SELECT vid FROM " + "group_" + group_id + " WHERE seed  = ?";
            System.out.println(sql);
            preparedStatement = connection.prepareStatement(sql);
            preparedStatement.setString(1, seed);
//            preparedStatement.setInt(1, Integer.parseInt(age));


            ResultSet resultSet = preparedStatement.executeQuery();
            System.out.println("group size : " + resultSet.getFetchSize());
            int count = 1;
            while(resultSet.next())
            {

//                System.out.println(count);
//                System.out.println("a : " + resultSet.getString("a"));
                //一一比對所有此group的成員是否為群簽章簽署者
                System.out.println(resultSet.getString("vid"));
                disclosureVid = resultSet.getString("vid");

//                count++;
//                System.out.println("next");
            }

            resultSet.close();
//            statement.close();
            connection.close();
            preparedStatement.close();
            System.out.println("db connection close");
        } catch (ClassNotFoundException e)
        {
            e.printStackTrace();
        } catch (SQLException e)
        {
            e.printStackTrace();
        }

        return disclosureVid;
    }

    public static void createTableRegist(String name)
    {
        System.out.println(name);
        String tableName;
        Connection connection = null;
        PreparedStatement preparedStatement = null;
        try
        {

            for(int i = 0; i < 800; i++)
            {
                Class.forName("org.sqlite.JDBC");
                connection = DriverManager.getConnection("jdbc:sqlite:RA.db");
                System.out.println("open database successfully");
                tableName = "group_" + i;
                String sql = "CREATE TABLE " + tableName + " "+
                        "(id INTEGER PRIMARY KEY   AUTOINCREMENT," +
                        "seed          TEXT    DEFAULT NULL," +
                        "group_id       INT     NOT NULL," +
                        "vid           TEXT    DEFAULT NULL";
                System.out.println("table :" + i);
                preparedStatement = connection.prepareStatement(sql);
//            preparedStatement.setString(1, name);
                preparedStatement.execute();
                preparedStatement.close();
                connection.close();
                System.out.println("RA regist tableconnection and prepareStatement close");
            }


        } catch (ClassNotFoundException e)
        {
            e.printStackTrace();
        } catch (SQLException e)
        {
            e.printStackTrace();
        }
        finally
        {

        }


    }
}
