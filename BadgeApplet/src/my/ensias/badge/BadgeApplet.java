/** 
 * Copyright (c) 1998, 2025, Oracle and/or its affiliates. All rights reserved.
 * 
 */


package my.ensias.badge;

import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.*;
/**
 * Applet class
 * 
 * @author <user>
 */

public class BadgeApplet extends Applet {

    
// Instructions APDU
private static final byte INS_SET_PIN = (byte) 0x10;
private static final byte INS_VERIFY_PIN = (byte) 0x20;
private static final byte INS_STORE_KEY = (byte) 0x30;
private static final byte INS_GET_KEY = (byte) 0x40;
private static final byte INS_RESET_TRIES = (byte) 0x50;
private static final byte INS_GET_USER_ID = (byte) 0x60;
private static final byte INS_GET_ANOMALY = (byte) 0x70;

// Constantes
private static final byte PIN_TRY_LIMIT = (byte) 3;
private static final byte MAX_PIN_SIZE = (byte) 8;
private static final short KEY_SIZE = (short) 16;
private static final short USER_ID_SIZE = (short) 16;
private static final short IV_SIZE = (short) 16;

// Constantes anomalies
private static final byte MAX_FAILED_ATTEMPTS = (byte) 5;
private static final short ANOMALY_FAILED_PIN = 0x0001;
private static final short ANOMALY_BLOCKED_PIN = 0x0002;
private static final short ANOMALY_UNAUTHORIZED_GET_KEY = 0x0004;
private static final short ANOMALY_WRONG_KEY_SIZE = 0x0008;
private static final short ANOMALY_RAPID_REQUESTS = 0x0010;

// Codes d'erreur
private static final short SW_PIN_VERIFICATION_REQUIRED = 0x6301;
private static final short SW_PIN_TRIES_REMAINING = 0x63C0;

// Stockage
private OwnerPIN pin;
private byte[] encryptedKey;
private byte[] iv;
private byte[] aesKey; 
private byte[] userId;
private short userIdLength;
private AESKey cryptoKey;
private Cipher cipher;
private RandomData random;
private boolean pinVerified;
private boolean keyStored;

// Détection anomalies
private short anomalyFlags;
private byte failedPinAttempts;
private byte requestCount;
private byte lastInstruction;

private BadgeApplet(byte[] bArray, short bOffset, byte bLength) {
    pin = new OwnerPIN(PIN_TRY_LIMIT, MAX_PIN_SIZE);
    
    encryptedKey = new byte[KEY_SIZE];
    iv = new byte[IV_SIZE];
    aesKey = new byte[KEY_SIZE];
    userId = new byte[USER_ID_SIZE];
    userIdLength = 0;
    keyStored = false;
    
    cryptoKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, 
                                              KeyBuilder.LENGTH_AES_128, 
                                              false);
    cipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
    random = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
    
    pinVerified = false;
    
    // Initialiser détection anomalies
    anomalyFlags = 0;
    failedPinAttempts = 0;
    requestCount = 0;
    lastInstruction = 0;
    
    register();
}

public static void install(byte[] bArray, short bOffset, byte bLength) {
    new BadgeApplet(bArray, bOffset, bLength);
}

public boolean select() {
    pinVerified = false;
    return true;
}

public void deselect() {
    pin.reset();
    pinVerified = false;
    Util.arrayFillNonAtomic(aesKey, (short)0, KEY_SIZE, (byte)0);
}

public void process(APDU apdu) {
    if (selectingApplet()) {
        return;
    }
    
    byte[] buffer = apdu.getBuffer();
    byte ins = buffer[ISO7816.OFFSET_INS];
    
    // Vérifier les requêtes rapides répétées
    checkRapidRequests(ins);
    
    switch (ins) {
        case INS_SET_PIN: setPin(apdu); break;
        case INS_VERIFY_PIN: verifyPin(apdu); break;
        case INS_STORE_KEY: storeEncryptedKey(apdu); break;
        case INS_GET_KEY: getDecryptedKey(apdu); break;
        case INS_RESET_TRIES: resetPinTries(apdu); break;
        case INS_GET_USER_ID: getUserId(apdu); break;
        case INS_GET_ANOMALY: getAnomalyStatus(apdu); break;
        default: ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
    }
}

private void checkRapidRequests(byte currentInstruction) {
    // Si même instruction appelée plusieurs fois = attaque potentielle
    if (currentInstruction == lastInstruction) {
        requestCount++;
        if (requestCount > 5) {
            anomalyFlags |= ANOMALY_RAPID_REQUESTS;
        }
    } else {
        requestCount = 1;
        lastInstruction = currentInstruction;
    }
}

private void setPin(APDU apdu) {
    byte[] buffer = apdu.getBuffer();
    short bytesRead = apdu.setIncomingAndReceive();

    byte pinLength = buffer[ISO7816.OFFSET_CDATA];
    if (pinLength > MAX_PIN_SIZE || pinLength <= 0) {
        ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    pin.update(buffer, (short)(ISO7816.OFFSET_CDATA + 1), pinLength);

    short userIdOffset = (short)(ISO7816.OFFSET_CDATA + 1 + pinLength);
    userIdLength = (short)(bytesRead - 1 - pinLength);

    if (userIdLength > 0 && userIdLength <= USER_ID_SIZE) {
        Util.arrayCopy(buffer, userIdOffset, userId, (short)0, userIdLength);
        Util.arrayFillNonAtomic(userId, userIdLength, (short)(USER_ID_SIZE - userIdLength), (byte)0);
    } else {
        userIdLength = 0;
        Util.arrayFillNonAtomic(userId, (short)0, USER_ID_SIZE, (byte)0);
    }

    deriveAESKey(buffer, (short)(ISO7816.OFFSET_CDATA + 1), pinLength);
    
    failedPinAttempts = 0;
}

private void verifyPin(APDU apdu) {
    byte[] buffer = apdu.getBuffer();
    byte lc = buffer[ISO7816.OFFSET_LC];
    if (lc > MAX_PIN_SIZE) {
        ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    }
    apdu.setIncomingAndReceive();
    
    if (pin.check(buffer, ISO7816.OFFSET_CDATA, lc)) {
        pinVerified = true;
        failedPinAttempts = 0;
    } else {
        pinVerified = false;
        failedPinAttempts++;
        
        if (failedPinAttempts >= MAX_FAILED_ATTEMPTS) {
            anomalyFlags |= ANOMALY_FAILED_PIN;
        }
        
        byte triesRemaining = pin.getTriesRemaining();
        if (triesRemaining == 0) {
            anomalyFlags |= ANOMALY_BLOCKED_PIN;
            ISOException.throwIt(ISO7816.SW_FILE_INVALID);
        } else {
            ISOException.throwIt((short)(SW_PIN_TRIES_REMAINING | triesRemaining));
        }
    }
}

private void storeEncryptedKey(APDU apdu) {
    if (!pinVerified) {
        ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
    }
    byte[] buffer = apdu.getBuffer();
    short bytesRead = apdu.setIncomingAndReceive();
    if (bytesRead != KEY_SIZE) {
        anomalyFlags |= ANOMALY_WRONG_KEY_SIZE;
        ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    }
    
    random.generateData(iv, (short)0, IV_SIZE);
    
    cipher.init(cryptoKey, Cipher.MODE_ENCRYPT, iv, (short)0, IV_SIZE);
    cipher.doFinal(buffer, ISO7816.OFFSET_CDATA, KEY_SIZE, encryptedKey, (short)0);
    
    keyStored = true;
}

private void getDecryptedKey(APDU apdu) {
    if (!keyStored) {
        ISOException.throwIt(ISO7816.SW_FILE_INVALID);
    }
    if (!pinVerified) {
        anomalyFlags |= ANOMALY_UNAUTHORIZED_GET_KEY;
        ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
    }
    byte[] buffer = apdu.getBuffer();
    
    cipher.init(cryptoKey, Cipher.MODE_DECRYPT, iv, (short)0, IV_SIZE);
    cipher.doFinal(encryptedKey, (short)0, KEY_SIZE, buffer, (short)0);
    
    apdu.setOutgoingAndSend((short)0, KEY_SIZE);
}

private void resetPinTries(APDU apdu) {
    pin.resetAndUnblock();
    anomalyFlags &= ~ANOMALY_BLOCKED_PIN;
    failedPinAttempts = 0;
}

private void getUserId(APDU apdu) {
    byte[] buffer = apdu.getBuffer();
    if (userIdLength > 0) {
        Util.arrayCopy(userId, (short)0, buffer, (short)0, userIdLength);
        apdu.setOutgoingAndSend((short)0, userIdLength);
    } else {
        apdu.setOutgoingAndSend((short)0, (short)0);
    }
}

private void getAnomalyStatus(APDU apdu) {
    byte[] buffer = apdu.getBuffer();
    
    buffer[0] = (byte)((anomalyFlags >> 8) & 0xFF);
    buffer[1] = (byte)(anomalyFlags & 0xFF);
    buffer[2] = failedPinAttempts;
    buffer[3] = (byte)(pin.getTriesRemaining() & 0xFF);
    
    apdu.setOutgoingAndSend((short)0, (short)4);
}

private void deriveAESKey(byte[] pinData, short offset, byte length) {
    Util.arrayFillNonAtomic(aesKey, (short)0, KEY_SIZE, (byte)0);
    
    for (short i = 0; i < length; i++) {
        byte pinByte = pinData[(short)(offset + i)];
        short keyIndex = (short)(i % KEY_SIZE);
        
        aesKey[keyIndex] ^= pinByte;
        aesKey[keyIndex] = rotateLeft(aesKey[keyIndex], (byte)((i + 1) % 8));
    }
    
    for (short i = 0; i < KEY_SIZE; i++) {
        aesKey[i] ^= (byte)(i + 0x55);
    }
    
    cryptoKey.setKey(aesKey, (short)0);
}

private byte rotateLeft(byte value, byte bits) {
    byte v = (byte)(value & 0xFF);
    return (byte)(((v << bits) | (v >> (8 - bits))) & 0xFF);
}

}
