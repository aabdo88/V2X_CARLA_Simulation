/*
 * (C) Copyright 2017, 2018 Crash Avoidance Metrics Partners LLC, VSC5 Consortium
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.campllc.mbrbuilder.service;

import com.oss.asn1.OctetString;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.campllc.asn1.generated.ieee1609dot2.*;
import org.campllc.asn1.generated.ieee1609dot2basetypes.*;
import org.campllc.asn1.generated.ieee1609dot2scmsbasetypes.LinkageChainId;
import org.campllc.mbrbuilder.objects.CommMsg;
import org.campllc.mbrbuilder.objects.CurvePoint;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;

@Service
public class EncryptionService {
    private static Log log = LogFactory.getLog(EncryptionService.class);

    @Value("${sharedFilesDirectory}")
    String sharedFilesDirectory;

    @Value("${componentCertificateDirectory}")
    String componentCertificatePath;

    @Autowired
    private CertificateReaderService certificateReaderService;

    @Autowired
    private ASNEncoder asnEncoder;

    @Autowired
    private PythonRunner pythonRunner;

    public class EncryptionResult {
        public String recipHashedId;
        public String ephemeralPubKey;
        public String encryptedAESKey;
        public String authTag;
        public String nonce;
        public String cipherText;
    }

    public class DecryptionParameters {
        public EccP256CurvePoint y; // ephemeral public key of sender
        public OctetString c; // encrypted symmetric key
        public OctetString t; // authentication tag
        public OctetString nonce; // AES nonce
        public OctetString ciphertext; // AES ciphertext
    }

    public EncryptionResult encrypt(String hexMessage, String cert, String receipientKey, int yPointUsed) throws InterruptedException, IOException {
        EncryptionResult result = null;
        boolean passAsFile = true;
        ArrayList<String> arguments = new ArrayList<>();
        if (passAsFile) {
            File bytesRequestFile = new File(sharedFilesDirectory, "etencrypt_file.oer");
            FileOutputStream fileOutputStream = new FileOutputStream(bytesRequestFile.getPath());
            PrintWriter printWriter = new PrintWriter(fileOutputStream);
            printWriter.print(hexMessage);
            String fullFilePath = sharedFilesDirectory + "etencrypt_file.oer";
            printWriter.close();
            arguments.add("-c");
            arguments.add('"' + fullFilePath + '"');
        } else {
            arguments.add("-p");
            arguments.add(hexMessage);
        }

        arguments.add("-f");
        arguments.add('"'+cert+'"');
        arguments.add("-r");
        arguments.add(receipientKey);
        arguments.add("-y");
        arguments.add(String.valueOf(yPointUsed));
        String[] output = pythonRunner.runPythonScript("etencrypt_file.py", arguments);

        result = new EncryptionResult();
        result.recipHashedId=output[0];
        result.ephemeralPubKey=output[1].substring(20,84);
        result.encryptedAESKey=output[2];
        result.authTag=output[3];
        result.nonce=output[4];
        result.cipherText=output[5];
        return result;
    }

    public LinkageChainId createLinkageChainId(byte[] linkageSeedValue) throws DecoderException, Exception{
        // recipKey is the private key communicated out of band
        String laChoice = "la1";
        String recipKey = getRecipientKey(laChoice);
        ArrayList<String> arguments = new ArrayList<>();
        arguments.add("-d");
        arguments.add(Hex.encodeHexString(linkageSeedValue));
        arguments.add("-r");
        arguments.add(recipKey);
        String[] symmetricEncryptOutput = pythonRunner.runPythonScript("symmetric_encryption.py",arguments);
        String dataCiphertext= symmetricEncryptOutput[0];
        String dataNonce = symmetricEncryptOutput[1];
        String dataKey = symmetricEncryptOutput[2];
        String recipCiphertext = symmetricEncryptOutput[3];
        String recipNonce = symmetricEncryptOutput[4];

        // Use recipKeyCreate to create SymmetricKey Object
        OctetString aesccm = new OctetString(Hex.decodeHex(recipKey.toCharArray()));
        SymmetricEncryptionKey symmetricEncryptionKey = SymmetricEncryptionKey.createSymmetricEncryptionKeyWithAes128Ccm(aesccm);

        // Use dataNonce, dataKey, and dataCiphertext to create SymmetricCipherText
        OctetString dataNonceOctet = new OctetString(Hex.decodeHex(dataNonce.toCharArray()));
        Opaque ccmCiphertext = new Opaque(Hex.decodeHex(dataCiphertext.toCharArray()));
        AesCcmCiphertext dataAesCcmCiphertext = new AesCcmCiphertext(dataNonceOctet,ccmCiphertext);
        SymmetricCiphertext dataSymCcmCiphertext = SymmetricCiphertext.createSymmetricCiphertextWithAes128ccm(dataAesCcmCiphertext);

        // Use recipNonce and recipCiphertext to create SymmetricCipherText
        Opaque recipCipherText = new Opaque(recipCiphertext.getBytes());
        OctetString recipNonceOctet = new OctetString(Hex.decodeHex(recipNonce.toCharArray()));
        AesCcmCiphertext recipAesCcmCiphertext = new AesCcmCiphertext(recipNonceOctet,recipCipherText);
        SymmetricCiphertext symmetricCiphertext = SymmetricCiphertext.createSymmetricCiphertextWithAes128ccm(recipAesCcmCiphertext);

        // Turn symmetricEncryptionKey from above into HashedId8
        byte[] symmetricEncryptionKeyBytes = asnEncoder.simpleEncode(symmetricEncryptionKey).getMsg();
        String symmetricEncryptionKeyHex = Hex.encodeHexString(symmetricEncryptionKeyBytes);
        ArrayList<String> hashEightArguments = new ArrayList<>();
        hashEightArguments.add("-d");
        hashEightArguments.add(symmetricEncryptionKeyHex);
        String[] hasheightEncryptOutput = pythonRunner.runPythonScript("HashedId8Computer.py",hashEightArguments);
        String hashedEightHexEncodedBytes = hasheightEncryptOutput[0];
        HashedId8 hashedId8 = new HashedId8(Hex.decodeHex(hashedEightHexEncodedBytes.toCharArray()));

        // Create SymmRecipientInfo
        SymmRecipientInfo symmRecipientInfo = new SymmRecipientInfo(hashedId8, symmetricCiphertext);
        RecipientInfo[] recipient=new RecipientInfo[1];
        recipient[0] = RecipientInfo.createRecipientInfoWithSymmRecipInfo(symmRecipientInfo);
        SequenceOfRecipientInfo recipientInfos = new SequenceOfRecipientInfo(recipient);
        //Create Linkage Chain Id
        LinkageChainId linkageChainId = new LinkageChainId(recipientInfos,dataSymCcmCiphertext);
        log.info("Linkage Chain Id = " + linkageChainId);
        return linkageChainId;
    }

    public CommMsg encryptIntoDot2DataBytes(String hexMessage, String certFile) throws Exception {
        Ieee1609Dot2Data dot2Data = encryptIntoDot2Data(hexMessage, certFile);
        return asnEncoder.simpleEncode(dot2Data);
    }

    public Ieee1609Dot2Data encryptIntoDot2Data(String hexMessage, String certFile) throws IOException, InterruptedException, DecoderException, DecoderException {
        // get the recipient key from the certificate
        Certificate certificate = certificateReaderService.readCertificateFromFile(certFile);
        CurvePoint publicKeyCurvePoint = new CurvePoint();
        publicKeyCurvePoint.readFromEccP256CurvePoint(certificate.getToBeSigned().getEncryptionKey().getPublicKey().getEciesNistP256());
        String recipientKey = Hex.encodeHexString(publicKeyCurvePoint.getyValue());

        // encrypt the data using the key
        EncryptionResult encryptionResult = encrypt(hexMessage, certFile, recipientKey, publicKeyCurvePoint.getyPoint());

        // fill in the dot2 structure using the results
        EccP256CurvePoint curvePoint = publicKeyCurvePoint.createEccP256CurvePoint(
                Hex.decodeHex(encryptionResult.ephemeralPubKey.toCharArray())
        );
        EncryptedDataEncryptionKey encryptionKey = EncryptedDataEncryptionKey.createEncryptedDataEncryptionKeyWithEciesNistP256(
                new EciesP256EncryptedKey(
                        curvePoint,
                        new OctetString(Hex.decodeHex(encryptionResult.encryptedAESKey.toCharArray())),
                        new OctetString(Hex.decodeHex(encryptionResult.authTag.toCharArray()))
                ));
        PKRecipientInfo certRecipientInfo = new PKRecipientInfo(
                new HashedId8(Hex.decodeHex(encryptionResult.recipHashedId.toCharArray())), encryptionKey);

        RecipientInfo[] recipient=new RecipientInfo[1];
        //can either be createWithCert or createWithSignedData
        recipient[0] = RecipientInfo.createRecipientInfoWithCertRecipInfo(certRecipientInfo);
        SequenceOfRecipientInfo recipientInfos = new SequenceOfRecipientInfo(recipient);
        AesCcmCiphertext aesCcmCiphertext = new AesCcmCiphertext(new OctetString(
                Hex.decodeHex(encryptionResult.nonce.toCharArray())),
                new Opaque(Hex.decodeHex(encryptionResult.cipherText.toCharArray())));
        EncryptedData encryptedData = new EncryptedData(recipientInfos,
                SymmetricCiphertext.createSymmetricCiphertextWithAes128ccm(aesCcmCiphertext));

        Ieee1609Dot2Content content = Ieee1609Dot2Content.createIeee1609Dot2ContentWithEncryptedData(encryptedData);
        Ieee1609Dot2Data encryptedDot2Data = new Ieee1609Dot2Data(new Uint8(3), content);
        return encryptedDot2Data;
    }

    public DecryptionParameters captureDecryptionParameters(Ieee1609Dot2Data dot2Data) {
        DecryptionParameters decryptionParameters = new DecryptionParameters();
        EncryptedData encryptedData  = dot2Data.getContent().getEncryptedData();

        // data set 1
        EciesP256EncryptedKey encryptedKey = encryptedData.getRecipients().get(0).getCertRecipInfo().getEncKey().getEciesNistP256();
        decryptionParameters.y = encryptedKey.getV();
        decryptionParameters.c = encryptedKey.getC();
        decryptionParameters.t = encryptedKey.getT();
        // data set 2
        AesCcmCiphertext aesCcmCiphertext = encryptedData.getCiphertext().getAes128ccm();
        decryptionParameters.nonce = aesCcmCiphertext.getNonce();
        decryptionParameters.ciphertext = aesCcmCiphertext.getCcmCiphertext();

        return decryptionParameters;
    }

    public CommMsg decryptDot2Data(Ieee1609Dot2Data dot2Data, File certificateFile,  File privateKeyFile) throws DecoderException, IOException {
        DecryptionParameters decryptionParameters = captureDecryptionParameters(dot2Data);
        CurvePoint curvePoint = new CurvePoint();
        curvePoint.readFromEccP256CurvePoint(decryptionParameters.y);
        byte[] privateKeyBytes = Files.readAllBytes(Paths.get(privateKeyFile.getAbsolutePath()));
        byte[] certificateBytes = Files.readAllBytes(Paths.get(certificateFile.getAbsolutePath()));
        ArrayList<String> arguments = new ArrayList<>();
        arguments.add("-y");
        arguments.add(Integer.toString(curvePoint.getyPoint()));
        arguments.add("--yValue");
        arguments.add(Hex.encodeHexString(curvePoint.getyValue()));
        arguments.add("-c");
        arguments.add(Hex.encodeHexString(decryptionParameters.c.byteArrayValue()));
        arguments.add("-t");
        arguments.add(Hex.encodeHexString(decryptionParameters.t.byteArrayValue()));
        arguments.add("--nonce");
        arguments.add(Hex.encodeHexString(decryptionParameters.nonce.byteArrayValue()));
        arguments.add("--ciphertext");
        arguments.add(Hex.encodeHexString(decryptionParameters.ciphertext.byteArrayValue()));
        arguments.add("--certificate");
        arguments.add(Hex.encodeHexString(certificateBytes));
        arguments.add("-p");
        arguments.add(Hex.encodeHexString(privateKeyBytes));
        String[] decryptOutput = pythonRunner.runPythonScript("decrypt_data.py",arguments);
        log.info("decrypt output = " + decryptOutput[0]);
        return new CommMsg(Hex.decodeHex(decryptOutput[0].toCharArray()));
    }

    public org.campllc.asn1.generatedmai.ieee1609dot2.EncryptedData createEncryptedPLV(org.campllc.asn1.generatedmai.ieee1609dot2scmsbasetypes.ToBeEncryptedIndividualPLV toBeEncryptedIndividualPLV) throws DecoderException, Exception{
         // recipKey is the private key communicated out of band
         String laChoice = "la2";
         String recipKey = getRecipientKey(laChoice);

         byte[] toBeEncryptedIndividualPLVBytes = asnEncoder.simpleEncode(toBeEncryptedIndividualPLV).getMsg();
         String toBeEncryptedIndividualPLVHexEncBytes = Hex.encodeHexString(toBeEncryptedIndividualPLVBytes);
         byte[]  EIPLVCheck = Hex.decodeHex(toBeEncryptedIndividualPLVHexEncBytes.toCharArray());
         InputStream is = new ByteArrayInputStream(EIPLVCheck);
         org.campllc.asn1.generatedmai.ieee1609dot2scmsbasetypes.ToBeEncryptedIndividualPLV checkPLv = asnEncoder.decodeToBeEncryptedIndividualPLV(is);
         ArrayList<String> arguments = new ArrayList<>();
         arguments.add("-d");
         arguments.add(toBeEncryptedIndividualPLVHexEncBytes);
         arguments.add("-r");
         arguments.add(recipKey);
         String[] symmetricEncryptOutput = pythonRunner.runPythonScript("symmetric_encryption.py",arguments);
         String dataCiphertext= symmetricEncryptOutput[0];
         String dataNonce = symmetricEncryptOutput[1];
         String dataKey = symmetricEncryptOutput[2];
         String recipCiphertext = symmetricEncryptOutput[3];
         String recipNonce = symmetricEncryptOutput[4];

         // Use recipKeyCreate to create SymmetricKey Object
         OctetString aesccm = new OctetString(Hex.decodeHex(recipKey.toCharArray()));
         org.campllc.asn1.generatedmai.ieee1609dot2basetypes.SymmetricEncryptionKey symmetricEncryptionKey = org.campllc.asn1.generatedmai.ieee1609dot2basetypes.SymmetricEncryptionKey.createSymmetricEncryptionKeyWithAes128Ccm(aesccm);

         // Use dataNonce, dataKey, and dataCiphertext to create SymmetricCipherText
         OctetString dataNonceOctet = new OctetString(Hex.decodeHex(dataNonce.toCharArray()));
         org.campllc.asn1.generatedmai.ieee1609dot2basetypes.Opaque ccmCiphertext = new org.campllc.asn1.generatedmai.ieee1609dot2basetypes.Opaque(Hex.decodeHex(dataCiphertext.toCharArray()));
         org.campllc.asn1.generatedmai.ieee1609dot2.AesCcmCiphertext dataAesCcmCiphertext = new org.campllc.asn1.generatedmai.ieee1609dot2.AesCcmCiphertext(dataNonceOctet,ccmCiphertext);
         org.campllc.asn1.generatedmai.ieee1609dot2.SymmetricCiphertext dataSymCcmCiphertext = org.campllc.asn1.generatedmai.ieee1609dot2.SymmetricCiphertext.createSymmetricCiphertextWithAes128ccm(dataAesCcmCiphertext);

         // Use recipNonce and recipCiphertext to create SymmetricCipherText
         org.campllc.asn1.generatedmai.ieee1609dot2basetypes.Opaque recipCipherText = new org.campllc.asn1.generatedmai.ieee1609dot2basetypes.Opaque(recipCiphertext.getBytes());
         OctetString recipNonceOctet = new OctetString(Hex.decodeHex(recipNonce.toCharArray()));
         org.campllc.asn1.generatedmai.ieee1609dot2.AesCcmCiphertext recipAesCcmCiphertext = new org.campllc.asn1.generatedmai.ieee1609dot2.AesCcmCiphertext(recipNonceOctet,recipCipherText);
         org.campllc.asn1.generatedmai.ieee1609dot2.SymmetricCiphertext symmetricCiphertext = org.campllc.asn1.generatedmai.ieee1609dot2.SymmetricCiphertext.createSymmetricCiphertextWithAes128ccm(recipAesCcmCiphertext);

         // Turn symmetricEncryptionKey from above into HashedId8
         byte[] symmetricEncryptionKeyBytes = asnEncoder.simpleEncode(symmetricEncryptionKey).getMsg();
         String symmetricEncryptionKeyHex = Hex.encodeHexString(symmetricEncryptionKeyBytes);
         ArrayList<String> hashEightArguments = new ArrayList<>();
         hashEightArguments.add("-d");
         hashEightArguments.add(symmetricEncryptionKeyHex);
         String[] hasheightEncryptOutput = pythonRunner.runPythonScript("HashedId8Computer.py",hashEightArguments);
         String hashedEightHexEncodedBytes = hasheightEncryptOutput[0];
         org.campllc.asn1.generatedmai.ieee1609dot2basetypes.HashedId8 hashedId8 = new org.campllc.asn1.generatedmai.ieee1609dot2basetypes.HashedId8(Hex.decodeHex(hashedEightHexEncodedBytes.toCharArray()));

         // Create SymmRecipientInfo
         org.campllc.asn1.generatedmai.ieee1609dot2.SymmRecipientInfo symmRecipientInfo = new org.campllc.asn1.generatedmai.ieee1609dot2.SymmRecipientInfo(hashedId8, symmetricCiphertext);
         org.campllc.asn1.generatedmai.ieee1609dot2.RecipientInfo[] recipient=new org.campllc.asn1.generatedmai.ieee1609dot2.RecipientInfo[1];
         recipient[0] = org.campllc.asn1.generatedmai.ieee1609dot2.RecipientInfo.createRecipientInfoWithSymmRecipInfo(symmRecipientInfo);
         org.campllc.asn1.generatedmai.ieee1609dot2.SequenceOfRecipientInfo recipientInfos = new org.campllc.asn1.generatedmai.ieee1609dot2.SequenceOfRecipientInfo(recipient);
         //Create Encrypted PLV
         org.campllc.asn1.generatedmai.ieee1609dot2.EncryptedData encryptedPLV = new org.campllc.asn1.generatedmai.ieee1609dot2.EncryptedData(recipientInfos,dataSymCcmCiphertext);
         CommMsg encryptedMessage = asnEncoder.simpleEncode(encryptedPLV);
         File file = new File("EncryptedIndividualPLV.oer");
         FileOutputStream encryptedFileOutputStream = new FileOutputStream(file);
         encryptedFileOutputStream.write(encryptedMessage.getMsg());
         log.info("Encrypted PLV = " + encryptedPLV);
         return encryptedPLV;
     }

     public String getRecipientKey(String laChoice) throws FileNotFoundException, IOException{
        String symmetricKeyPath = componentCertificatePath + "\\" + laChoice + "-symmetric.key";
        File symmetricKeyFile = new File(symmetricKeyPath);
        FileReader fileReader = new FileReader(symmetricKeyFile);
        BufferedReader bufferedReader = new BufferedReader(fileReader);
        String recipKey = bufferedReader.readLine();
        return recipKey;
     }
}
