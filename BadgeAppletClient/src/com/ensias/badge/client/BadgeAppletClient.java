package com.ensias.badge.client;

import javax.smartcardio.*;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.*;
import java.security.NoSuchAlgorithmException;
import java.text.SimpleDateFormat;
import java.util.*;
import java.net.InetSocketAddress;


public class BadgeAppletClient {

    private static final byte[] APPLET_AID = {
        (byte)0x20, (byte)0x20, (byte)0x20, (byte)0x20, (byte)0x20
    };

    private static final byte INS_SET_PIN = (byte) 0x10;
    private static final byte INS_VERIFY_PIN = (byte) 0x20;
    private static final byte INS_STORE_KEY = (byte) 0x30;
    private static final byte INS_GET_KEY = (byte) 0x40;
    private static final byte INS_RESET_TRIES = (byte) 0x50;
    private static final byte INS_GET_USER_ID = (byte) 0x60;
    private static final byte INS_GET_ANOMALY = (byte) 0x70;

    private static final int SESSION_TIMEOUT = 300;

    private Card card;
    private CardChannel channel;
    private Scanner scanner;
    private AccessLogger logger;
    private SessionManager sessionManager;
    private PINManager pinManager;

    public BadgeAppletClient() {
        scanner = new Scanner(System.in);
        logger = new AccessLogger();
        sessionManager = new SessionManager(SESSION_TIMEOUT);
        pinManager = new PINManager();
    }

    public static void main(String[] args) {
        BadgeAppletClient client = new BadgeAppletClient();
        try {
            client.connectToCard();
            client.run();
        } catch (Exception e) {
            System.err.println("Erreur: " + e.getMessage());
            e.printStackTrace();
        } finally {
            client.disconnect();
        }
    }

    
    private void connectToCard() throws Exception {
        System.out.println("=== ETAPE 1: Création SocketCardTerminal ===");
        
        TerminalFactory factory = TerminalFactory.getInstance(
            "SocketCardTerminalFactoryType",
            List.of(new InetSocketAddress("localhost", 9025)),
            "SocketCardTerminalProvider"
        );
        System.out.println("✓ TerminalFactory créée");

        System.out.println("\n=== ETAPE 2: Récupération des terminaux ===");
        List<CardTerminal> terminals = factory.terminals().list();
        System.out.println("Nombre de terminaux: " + terminals.size());
        
        if (terminals.isEmpty()) {
            throw new CardException("❌ ERREUR: Aucun terminal detecte - simulateur pas lancé?");
        }

        CardTerminal terminal = terminals.get(0);
        System.out.println("Terminal trouvé: " + terminal.getName());

        System.out.println("\n=== ETAPE 3: Tentative de connexion ===");
        try {
            card = terminal.connect("*");
            System.out.println("✓ Connexion établie avec la carte");
            System.out.println("  - Card Protocol: " + card.getProtocol());
        } catch (CardNotPresentException e) {
            System.out.println("❌ ERREUR: CardNotPresentException");
            System.out.println("  Cause: Applet pas sélectionnée dans le simulateur");
            throw e;
        }

        System.out.println("\n=== ETAPE 4: Obtention du BasicChannel ===");
        channel = card.getBasicChannel();
        System.out.println("✓ BasicChannel obtenu");

        System.out.println("\n=== ETAPE 5: Sélection de l'applet ===");
        ResponseAPDU response = channel.transmit(
            new CommandAPDU(0x00, 0xA4, 0x04, 0x00, APPLET_AID)
        );
        System.out.println("APDU sent: 00 A4 04 00 05 " + bytesToHex(APPLET_AID));
        System.out.println("Response SW: " + String.format("%04X", response.getSW()));
        System.out.println("Response data: " + bytesToHex(response.getBytes()));

        if (response.getSW() != 0x9000) {
            throw new CardException("❌ Applet non trouvée (SW=" + String.format("%04X", response.getSW()) + ")");
        }

        System.out.println("✓ Applet BadgeApplet sélectionnée\n");
    }

    
    /**
    private String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X ", b));
        }
        return sb.toString();
    } **/

    
    
    private void run() throws Exception {
        boolean running = true;
        
        while (running) {
            displayMenu();
            try {
                int choice = scanner.nextInt();
                scanner.nextLine();
                
                switch (choice) {
                    case 1:
                        initializeUser();
                        break;
                    case 2:
                        authenticate();
                        break;
                    
                        
                    case 3:
                        displayAccessLogs();
                        break;
                    case 4:
                        resetPinTries();
                        break;
                    case 5:
                        running = false;
                        System.out.println("Au revoir!\n");
                        break;
                    default:
                        System.out.println("Option invalide\n");
                }
            } catch (Exception e) {
                System.out.println("Erreur: " + e.getMessage() + "\n");
                scanner.nextLine();
            }
        }
    }

    private void displayMenu() {
        System.out.println("===== BADGE APPLET CLIENT =====");
        System.out.println("1. Initialiser badge (PIN + ID)");
        System.out.println("2. S'authentifier");
        // System.out.println("3. Verifier anomalies");
        System.out.println("3. Afficher logs");
        System.out.println("4. Debloquer PIN");
        System.out.println("5. Quitter");
        System.out.print("Choix: ");
    }

    private void initializeUser() throws Exception {
        System.out.println("\n===== INITIALISATION =====\n");
        
        System.out.print("ID Utilisateur (max 16 caracteres): ");
        String userId = scanner.nextLine();
        
        if (userId.isEmpty()) {
            System.out.println("ID vide\n");
            return;
        }
        
        if (userId.length() > 16) {
            userId = userId.substring(0, 16);
        }
        
        String pin = pinManager.requestNewPIN(scanner);
        
        if (pin == null) {
            System.out.println("PIN invalide (4-8 chiffres)\n");
            return;
        }

        byte[] pinBytes = pin.getBytes();
        byte[] userIdBytes = userId.getBytes();
        byte[] data = new byte[1 + pinBytes.length + userIdBytes.length];
        
        data[0] = (byte) pinBytes.length;
        System.arraycopy(pinBytes, 0, data, 1, pinBytes.length);
        System.arraycopy(userIdBytes, 0, data, 1 + pinBytes.length, userIdBytes.length);

        ResponseAPDU response = channel.transmit(
            new CommandAPDU(0x00, INS_SET_PIN, 0x00, 0x00, data)
        );

        if (response.getSW() != 0x9000) {
            System.out.println("Erreur SET_PIN\n");
            logger.logEvent(userId, "INIT_FAIL", "SET_PIN echoue");
            return;
        }

        response = channel.transmit(
            new CommandAPDU(0x00, INS_VERIFY_PIN, 0x00, 0x00, pinBytes)
        );

        if (response.getSW() != 0x9000) {
            System.out.println("Erreur VERIFY_PIN\n");
            return;
        }

        byte[] privateKey = generatePrivateKey();
        
        response = channel.transmit(
            new CommandAPDU(0x00, INS_STORE_KEY, 0x00, 0x00, privateKey)
        );

        if (response.getSW() != 0x9000) {
            System.out.println("Erreur STORE_KEY\n");
            logger.logEvent(userId, "INIT_FAIL", "STORE_KEY echoue");
            return;
        }

        System.out.println("Badge initialise avec succes!");
        System.out.println("ID: " + userId);
        System.out.println("PIN: " + "*".repeat(pin.length()));
        System.out.println("Cle privee (hex): " + bytesToHex(privateKey));
        System.out.println("Conservez cette cle en lieu sur!\n");
        
        logger.logEvent(userId, "BADGE_INIT", "Badge initialise");
    }

    private void authenticate() throws Exception {
        System.out.println("\n===== AUTHENTIFICATION =====\n");

        ResponseAPDU response = channel.transmit(
            new CommandAPDU(0x00, INS_GET_USER_ID, 0x00, 0x00, 16)
        );

        if (response.getSW() != 0x9000) {
            System.out.println("Erreur GET_USER_ID\n");
            return;
        }

        String userId = new String(response.getData()).trim();
        if (userId.isEmpty()) {
            System.out.println("Badge non initialise\n");
            return;
        }
        
        System.out.println("Badge detecte: " + userId);

        System.out.println("\n--- Facteur 1: Verification PIN ---");
        System.out.print("PIN: ");
        String pin = scanner.nextLine();

        response = channel.transmit(
            new CommandAPDU(0x00, INS_VERIFY_PIN, 0x00, 0x00, pin.getBytes())
        );

        int sw = response.getSW();
        
        if (sw != 0x9000) {
            if ((sw & 0xFFF0) == 0x63C0) {
                int remaining = sw & 0x0F;
                System.out.println("PIN incorrect. Tentatives restantes: " + remaining);
            } else if (sw == 0x6983) {
                System.out.println("Badge bloque");
            }
            logger.logEvent(userId, "AUTH_FAIL", "PIN incorrect");
            System.out.println();
            return;
        }

        System.out.println("PIN correct");
/**
        System.out.println("\n--- Verification anomalies ---");
        response = channel.transmit(
            new CommandAPDU(0x00, INS_GET_ANOMALY, 0x00, 0x00, 4)
        );

        if (response.getSW() == 0x9000) {
            byte[] anomalyData = response.getData();
            if (anomalyData.length >= 4) {
                short flags = (short)((anomalyData[0] << 8) | (anomalyData[1] & 0xFF));
                byte failedAttempts = anomalyData[2];
                byte triesRemaining = anomalyData[3];
                
                if (flags != 0) {
                    System.out.println("Anomalies detectees!");
                    System.out.println("Flags: 0x" + String.format("%04X", flags));
                    System.out.println("Tentatives echouees: " + failedAttempts);
                    System.out.println("Tentatives restantes: " + triesRemaining);
                    logger.logEvent(userId, "ANOMALY_DETECTED", "Flags: 0x" + String.format("%04X", flags));
                    System.out.println();
                    return;
                }
            }
        }
        
        System.out.println("Aucune anomalie");
        **/

        System.out.println("\n--- Facteur 2: Verification cle privee ---");
        
        response = channel.transmit(
            new CommandAPDU(0x00, INS_GET_KEY, 0x00, 0x00, 16)
        );

        if (response.getSW() != 0x9000) {
            System.out.println("Erreur recuperation cle\n");
            logger.logEvent(userId, "AUTH_FAIL", "GET_KEY echoue");
            return;
        }

        byte[] retrievedKey = response.getData();
        
        if (verifyCryptographicChallenge(retrievedKey)) {
            System.out.println("Cle privee valide");
            
            System.out.println("\n===== ACCES ACCORDE =====");
            System.out.println("Authentification A2F reussie!\n");
            
            String sessionId = sessionManager.createSession(userId);
            logger.logEvent(userId, "ACCESS_GRANTED", "Session: " + sessionId);
            
            manageSession(userId, sessionId);
            
        } else {
            System.out.println("Cle privee invalide\n");
            System.out.println("===== ACCES REFUSE =====\n");
            logger.logEvent(userId, "AUTH_FAIL", "Cle privee invalide");
        }
    }

    private void displayAnomalies() throws Exception {
        System.out.println("\n===== VERIFICATION ANOMALIES =====\n");
        
        ResponseAPDU response = channel.transmit(
            new CommandAPDU(0x00, INS_GET_USER_ID, 0x00, 0x00, 16)
        );

        if (response.getSW() != 0x9000) {
            System.out.println("Erreur lecture badge\n");
            return;
        }

        String userId = new String(response.getData()).trim();
        
        response = channel.transmit(
            new CommandAPDU(0x00, INS_GET_ANOMALY, 0x00, 0x00, 4)
        );

        if (response.getSW() == 0x9000) {
            byte[] data = response.getData();
            if (data.length >= 4) {
                short flags = (short)((data[0] << 8) | (data[1] & 0xFF));
                byte failedAttempts = data[2];
                byte triesRemaining = data[3];
                
                System.out.println("Utilisateur: " + userId);
                System.out.println("Flags anomalies: 0x" + String.format("%04X", flags));
                System.out.println("Tentatives echouees: " + failedAttempts);
                System.out.println("Tentatives restantes: " + triesRemaining + "\n");
            }
        }
    }

    private void displayAccessLogs() {
        System.out.println();
        logger.displayLogs();
        System.out.println();
    }

    private void resetPinTries() throws Exception {
        System.out.println("\n===== DEBLOCAGE PIN =====\n");
        
        ResponseAPDU response = channel.transmit(
            new CommandAPDU(0x00, INS_RESET_TRIES, 0x00, 0x00)
        );

        if (response.getSW() == 0x9000) {
            System.out.println("PIN debloque avec succes\n");
            logger.logEvent("SYSTEM", "PIN_RESET", "PIN reinitialise");
        } else {
            System.out.println("Erreur deblocage\n");
        }
    }

    private void manageSession(String userId, String sessionId) throws InterruptedException {
        System.out.println("Session ID: " + sessionId);
        System.out.println("Timeout: " + SESSION_TIMEOUT + "s");
        System.out.println("Appuyez sur Entree pour terminer...\n");
        
        scanner.nextLine();
        
        if (sessionManager.isSessionActive(sessionId)) {
            sessionManager.closeSession(sessionId);
            System.out.println("Session fermee\n");
            logger.logEvent(userId, "SESSION_CLOSED", "Fermee par utilisateur");
        }
    }

    private byte[] generatePrivateKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128);
        SecretKey secretKey = keyGen.generateKey();
        return secretKey.getEncoded();
    }

    private boolean verifyCryptographicChallenge(byte[] key) {
        if (key == null || key.length != 16) {
            return false;
        }
        
        for (byte b : key) {
            if (b != 0) {
                return true;
            }
        }
        
        return false;
    }

    private String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X ", b));
        }
        return sb.toString().trim();
    }
    
    
    
    
    

    private void disconnect() {
        try {
            if (card != null) {
                card.disconnect(false);
                System.out.println("Deconnecte du simulateur");
            }
        } catch (Exception e) {
            System.err.println("Erreur: " + e.getMessage());
        }
    }
}

class PINManager {
    public String requestNewPIN(Scanner scanner) {
        System.out.print("Definir PIN (4-8 chiffres): ");
        String pin = scanner.nextLine();
        
        if (!isValidPIN(pin)) {
            return null;
        }
        
        System.out.print("Confirmer PIN: ");
        String confirm = scanner.nextLine();
        
        if (!pin.equals(confirm)) {
            System.out.println("PINs ne correspondent pas");
            return null;
        }
        
        return pin;
    }
    
    private boolean isValidPIN(String pin) {
        return pin != null && pin.length() >= 4 && pin.length() <= 8 && pin.matches("\\d+");
    }
}

class SessionManager {
    private Map<String, SessionInfo> activeSessions = new HashMap<>();
    private int timeout;
    
    public SessionManager(int timeout) {
        this.timeout = timeout;
    }
    
    public String createSession(String userId) {
        String sessionId = UUID.randomUUID().toString().substring(0, 8);
        activeSessions.put(sessionId, new SessionInfo(userId, System.currentTimeMillis()));
        return sessionId;
    }
    
    public boolean isSessionActive(String sessionId) {
        return activeSessions.containsKey(sessionId);
    }
    
    public void closeSession(String sessionId) {
        activeSessions.remove(sessionId);
    }
    
    static class SessionInfo {
        String userId;
        long startTime;
        
        SessionInfo(String userId, long startTime) {
            this.userId = userId;
            this.startTime = startTime;
        }
    }
}

class AccessLogger {
    private List<LogEntry> logs = new ArrayList<>();
    private SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
    
    public void logEvent(String userId, String eventType, String details) {
        logs.add(new LogEntry(userId, eventType, details, new Date()));
        saveToFile(new LogEntry(userId, eventType, details, new Date()));
    }
    
    public void displayLogs() {
        if (logs.isEmpty()) {
            System.out.println("===== HISTORIQUE (vide) =====");
            return;
        }
        
        System.out.println("===== HISTORIQUE D'ACCES =====");
        System.out.println(String.format("%-19s | %-15s | %-15s | %-20s",
            "Date/Heure", "Utilisateur", "Type", "Details"));
        System.out.println("-".repeat(80));
        
        for (LogEntry log : logs) {
            String user = log.userId.length() > 15 ? log.userId.substring(0, 15) : log.userId;
            String type = log.eventType.length() > 15 ? log.eventType.substring(0, 15) : log.eventType;
            String details = log.details.length() > 20 ? log.details.substring(0, 20) : log.details;
            
            System.out.println(String.format("%-19s | %-15s | %-15s | %-20s",
                dateFormat.format(log.timestamp),
                user,
                type,
                details));
        }
    }
    
    private void saveToFile(LogEntry entry) {
        try (PrintWriter out = new PrintWriter(new FileWriter("badge_logs.txt", true))) {
            out.println(dateFormat.format(entry.timestamp) + " | " + entry.userId + 
                " | " + entry.eventType + " | " + entry.details);
        } catch (IOException e) {
            System.err.println("Erreur log: " + e.getMessage());
        }
    }
    
    static class LogEntry {
        String userId, eventType, details;
        Date timestamp;
        
        LogEntry(String userId, String eventType, String details, Date timestamp) {
            this.userId = userId;
            this.eventType = eventType;
            this.details = details;
            this.timestamp = timestamp;
        }
    }
}
