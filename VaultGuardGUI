import javax.swing.*;
import java.awt.*;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.awt.event.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.SecureRandom;
import java.util.*;
import java.util.concurrent.*;
import java.util.stream.Collectors;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;
import org.bouncycastle.util.encoders.Hex;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class VaultGuardGUI {
    private static final String HASH_FILE = "data/master.hash";
    private static final String VAULT_FILE = "data/passwords.vault";
    private static final String ACTIVITY_LOG_FILE = "data/activity.vault";
    private static final String CONFIG_FILE = "data/vaultguard.config";
    private static final String QUESTION_FILE = "data/master.hash.question.b64";
    private static final int LOGIN_DELAY = 2000; // milliseconds

    // Config class
    static class Config {
        private String configFilePath;
        private int sessionTimeout;
        private int passwordInputTimeout;
        private boolean autoBackup;

        public Config(String configFilePath) {
            this.configFilePath = configFilePath;
            this.sessionTimeout = 60; // Default to 60 seconds
            this.passwordInputTimeout = 30;
            this.autoBackup = false;
            loadConfig();
        }

        private void loadConfig() {
            try {
                if (!Files.exists(Paths.get(configFilePath))) {
                    saveConfig();
                    return;
                }
                Properties props = new Properties();
                try (FileInputStream fis = new FileInputStream(configFilePath)) {
                    props.load(fis);
                }
                sessionTimeout = Integer.parseInt(props.getProperty("session_timeout", "60"));
                passwordInputTimeout = Integer.parseInt(props.getProperty("password_input_timeout", "30"));
                autoBackup = Boolean.parseBoolean(props.getProperty("auto_backup", "false"));
                if (sessionTimeout < 60) sessionTimeout = 60;
                if (passwordInputTimeout < 10) passwordInputTimeout = 10;
            } catch (IOException | NumberFormatException e) {
                JOptionPane.showMessageDialog(null, "Error loading config: " + e.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
            }
        }

        private void saveConfig() {
            try {
                Properties props = new Properties();
                props.setProperty("session_timeout", String.valueOf(sessionTimeout));
                props.setProperty("password_input_timeout", String.valueOf(passwordInputTimeout));
                props.setProperty("auto_backup", String.valueOf(autoBackup));
                try (FileOutputStream fos = new FileOutputStream(configFilePath)) {
                    props.store(fos, "VaultGuard Configuration");
                }
            } catch (IOException e) {
                JOptionPane.showMessageDialog(null, "Error saving config: " + e.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
            }
        }

        public int getSessionTimeout() { return sessionTimeout; }
        public int getPasswordInputTimeout() { return passwordInputTimeout; }
        public boolean getAutoBackup() { return autoBackup; }
        public void setAutoBackup(boolean enabled) {
            this.autoBackup = enabled;
            saveConfig();
        }
    }

    // Encryption class (unchanged)
    static class Encryption {
        private static final int SALT_LENGTH = 16;
        private static final int NONCE_LENGTH = 12;
        private static final int KEY_LENGTH = 32;
        private static final int TAG_LENGTH = 16;

        public static String encrypt(String plaintext, String password) throws Exception {
            if (plaintext.isEmpty() || password.isEmpty()) return "";
            byte[] salt = generateRandomBytes(SALT_LENGTH);
            byte[] nonce = generateRandomBytes(NONCE_LENGTH);
            byte[] key = deriveKey(password, salt);

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
            GCMParameterSpec gcmSpec = new GCMParameterSpec(TAG_LENGTH * 8, nonce);
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec);

            byte[] ciphertext = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
            byte[] result = new byte[SALT_LENGTH + NONCE_LENGTH + ciphertext.length];
            System.arraycopy(salt, 0, result, 0, SALT_LENGTH);
            System.arraycopy(nonce, 0, result, SALT_LENGTH, NONCE_LENGTH);
            System.arraycopy(ciphertext, 0, result, SALT_LENGTH + NONCE_LENGTH, ciphertext.length);
            return Base64.getEncoder().encodeToString(result);
        }

        public static String decrypt(String ciphertext, String password) throws Exception {
            if (ciphertext.isEmpty() || password.isEmpty()) return "";
            byte[] data = Base64.getDecoder().decode(ciphertext);
            if (data.length < SALT_LENGTH + NONCE_LENGTH + TAG_LENGTH) return "";

            byte[] salt = Arrays.copyOfRange(data, 0, SALT_LENGTH);
            byte[] nonce = Arrays.copyOfRange(data, SALT_LENGTH, SALT_LENGTH + NONCE_LENGTH);
            byte[] encrypted = Arrays.copyOfRange(data, SALT_LENGTH + NONCE_LENGTH, data.length);
            byte[] key = deriveKey(password, salt);

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
            GCMParameterSpec gcmSpec = new GCMParameterSpec(TAG_LENGTH * 8, nonce);
            cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmSpec);
            byte[] plaintext = cipher.doFinal(encrypted);
            return new String(plaintext, StandardCharsets.UTF_8);
        }

        private static byte[] generateRandomBytes(int length) {
            byte[] bytes = new byte[length];
            new SecureRandom().nextBytes(bytes);
            return bytes;
        }

        private static byte[] deriveKey(String password, byte[] salt) {
            Argon2Parameters.Builder builder = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
                    .withSalt(salt)
                    .withParallelism(1)
                    .withMemoryAsKB(65536)
                    .withIterations(2);
            Argon2BytesGenerator generator = new Argon2BytesGenerator();
            generator.init(builder.build());
            byte[] key = new byte[KEY_LENGTH];
            generator.generateBytes(password.getBytes(StandardCharsets.UTF_8), key);
            return key;
        }

        public static String hashPassword(String password, String salt) {
            SHA256Digest digest = new SHA256Digest();
            byte[] input = (salt + password).getBytes(StandardCharsets.UTF_8);
            digest.update(input, 0, input.length);
            byte[] hash = new byte[digest.getDigestSize()];
            digest.doFinal(hash, 0);
            return Hex.toHexString(hash);
        }
    }

    // Entry class (unchanged)
    static class Entry {
        private String website, username, password, category;

        public Entry(String website, String username, String password, String category) {
            this.website = website;
            this.username = username;
            this.password = password;
            this.category = category;
        }

        public String getWebsite() { return website; }
        public String getUsername() { return username; }
        public String getPassword() { return password; }
        public String getCategory() { return category; }

        public String serialize() {
            return website + "\u001F" + username + "\u001F" + password + "\u001F" + category;
        }

        public static Entry deserialize(String data) {
            String[] parts = data.split("\u001F");
            if (parts.length != 4) throw new IllegalArgumentException("Invalid entry format");
            return new Entry(parts[0], parts[1], parts[2], parts[3]);
        }
    }

    // Logger class (unchanged)
    static class Logger {
        private String activityLogFile;
        private String masterPassword;

        public Logger(String activityLogFile) {
            this.activityLogFile = activityLogFile;
        }

        public void setMasterPassword(String password) {
            this.masterPassword = password;
        }

        public void logActivity(String type, String action, String details) {
            if (masterPassword == null || masterPassword.isEmpty()) return;
            String timestamp = new java.text.SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date());
            String logEntry = timestamp + " | " + type + ": " + action;
            if (!details.isEmpty()) logEntry += " | Details: " + details;
            logEntry += "\n--------------------\n";

            try {
                String encryptedEntry = Encryption.encrypt(logEntry, masterPassword);
                Files.write(Paths.get(activityLogFile), (encryptedEntry + "----ENTRY----").getBytes(),
                        StandardOpenOption.APPEND, StandardOpenOption.CREATE);
            } catch (Exception e) {
                JOptionPane.showMessageDialog(null, "Error logging activity: " + e.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
            }
        }

        public String getActivityLog() {
            if (masterPassword == null || masterPassword.isEmpty()) return "Error: Master password not set.\n";
            try {
                if (!Files.exists(Paths.get(activityLogFile))) return "No logs found.\n";
                String encryptedData = new String(Files.readAllBytes(Paths.get(activityLogFile)));
                if (encryptedData.isEmpty()) return "No logs found.\n";

                StringBuilder result = new StringBuilder();
                String[] segments = encryptedData.split("----ENTRY----");
                for (String segment : segments) {
                    if (!segment.isEmpty()) {
                        try {
                            String decrypted = Encryption.decrypt(segment, masterPassword);
                            if (!decrypted.isEmpty()) {
                                result.append(decrypted);
                            } else {
                                result.append("Warning: Failed to decrypt a log entry.\n");
                            }
                        } catch (Exception e) {
                            result.append("Warning: Failed to decrypt a log entry: " + e.getMessage() + "\n");
                        }
                    }
                }
                return result.length() > 0 ? result.toString() : "No logs found.\n";
            } catch (IOException e) {
                return "Error reading logs: " + e.getMessage() + "\n";
            }
        }

        public void clearLog() {
            try {
                Files.write(Paths.get(activityLogFile), new byte[0], StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.CREATE);
                logActivity("Action", "Cleared all logs", "");
            } catch (IOException e) {
                JOptionPane.showMessageDialog(null, "Error clearing logs: " + e.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    // PasswordGenerator class (unchanged)
    static class PasswordGenerator {
        private static final String UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        private static final String LOWER = "abcdefghijklmnopqrstuvwxyz";
        private static final String DIGITS = "0123456789";
        private static final String SPECIAL = "!@#$%^&*()_+-=[]{}|;:,.<>?";
        private static final SecureRandom random = new SecureRandom();

        public static String generatePassword(int length, boolean includeUpper, boolean includeLower,
                                             boolean includeDigits, boolean includeSpecial) {
            if (length < 8 || length > 128 || (!includeUpper && !includeLower && !includeDigits && !includeSpecial)) {
                return "";
            }
            StringBuilder chars = new StringBuilder();
            if (includeUpper) chars.append(UPPER);
            if (includeLower) chars.append(LOWER);
            if (includeDigits) chars.append(DIGITS);
            if (includeSpecial) chars.append(SPECIAL);

            StringBuilder password = new StringBuilder();
            for (int i = 0; i < length; i++) {
                password.append(chars.charAt(random.nextInt(chars.length())));
            }
            return password.toString();
        }
    }

    // Vault class
    static class Vault {
        private String hashFilePath, vaultFile, activityLogFile, configFilePath;
        private String masterHash, salt, securityAnswerHash, masterPassword, securityQuestion;
        private int loginAttempts, lockoutCount;
        private boolean isLocked;
        private long lockoutTime;
        private long lastActivity;
        private Logger logger;
        private Config config;

        public Vault(String hashFilePath, Logger logger, String vaultFile, String activityLogFile, String configFilePath) {
            this.hashFilePath = hashFilePath;
            this.vaultFile = vaultFile;
            this.activityLogFile = activityLogFile;
            this.configFilePath = configFilePath;
            this.logger = logger;
            this.config = new Config(configFilePath);
            this.loginAttempts = 0;
            this.lockoutCount = 0;
            this.isLocked = false;
            this.lockoutTime = 0;
            this.lastActivity = System.currentTimeMillis();
            createDataDirectory();
            readMasterData();
            readSecurityData();
        }

        private boolean createDataDirectory() {
            try {
                Files.createDirectories(Paths.get(hashFilePath).getParent());
                return true;
            } catch (IOException e) {
                JOptionPane.showMessageDialog(null, "Error creating data directory: " + e.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
                return false;
            }
        }

        private boolean readMasterData() {
            try {
                if (!Files.exists(Paths.get(hashFilePath))) return false;
                java.util.List<String> lines = Files.readAllLines(Paths.get(hashFilePath));
                if (lines.size() >= 2) {
                    masterHash = lines.get(0);
                    salt = lines.get(1);
                    loginAttempts = lines.size() > 2 ? Integer.parseInt(lines.get(2)) : 0;
                    securityAnswerHash = lines.size() > 3 ? lines.get(3) : "";
                    lockoutCount = lines.size() > 4 ? Integer.parseInt(lines.get(4)) : 0;
                    lockoutTime = lines.size() > 5 ? Long.parseLong(lines.get(5)) : 0;
                }
                return !masterHash.isEmpty() && !salt.isEmpty();
            } catch (IOException | NumberFormatException e) {
                return false;
            }
        }

        private boolean writeMasterData(String hash, String salt, String answerHash,
                                       int attempts, int lockoutCount, long lockoutTime) {
            try {
                String data = hash + "\n" + salt + "\n" + attempts + "\n" + answerHash + "\n" +
                              lockoutCount + "\n" + lockoutTime;
                Files.write(Paths.get(hashFilePath), data.getBytes(), StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
                return true;
            } catch (IOException e) {
                JOptionPane.showMessageDialog(null, "Error writing master data: " + e.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
                return false;
            }
        }

        private boolean readSecurityData() {
            try {
                if (!Files.exists(Paths.get(QUESTION_FILE))) return false;
                securityQuestion = new String(Base64.getDecoder().decode(Files.readString(Paths.get(QUESTION_FILE))));
                return !securityQuestion.isEmpty();
            } catch (IOException e) {
                return false;
            }
        }

        private boolean writeSecurityQuestion(String question) {
            try {
                Files.write(Paths.get(QUESTION_FILE), Base64.getEncoder().encode(question.getBytes()),
                        StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
                securityQuestion = question;
                return true;
            } catch (IOException e) {
                JOptionPane.showMessageDialog(null, "Error writing security question: " + e.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
                return false;
            }
        }

        private String generateSalt() {
            byte[] saltBytes = new byte[16];
            new SecureRandom().nextBytes(saltBytes);
            return Hex.toHexString(saltBytes);
        }

        private int getLockoutDuration() {
            if (loginAttempts < 3) return 0;
            if (loginAttempts < 6) return 120;
            if (loginAttempts < 9) return 300;
            return 600;
        }

        private boolean checkLockout() {
            if (!isLocked) return false;
            long now = System.currentTimeMillis() / 1000;
            long lockoutDuration = now - lockoutTime;
            int duration = getLockoutDuration();
            if (lockoutDuration >= duration) {
                isLocked = false;
                if (loginAttempts >= 10) {
                    JOptionPane.showMessageDialog(null, "Maximum attempts reached. Resetting vault...", "Error", JOptionPane.ERROR_MESSAGE);
                    logger.logActivity("Security", "Max attempts reached, vault reset", "");
                    try {
                        Files.deleteIfExists(Paths.get(hashFilePath));
                        Files.deleteIfExists(Paths.get(vaultFile));
                        Files.deleteIfExists(Paths.get(activityLogFile));
                        Files.deleteIfExists(Paths.get(QUESTION_FILE));
                    } catch (IOException e) {
                        JOptionPane.showMessageDialog(null, "Error resetting vault: " + e.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
                    }
                    loginAttempts = 0;
                    lockoutCount = 0;
                    lockoutTime = 0;
                    writeMasterData(masterHash, salt, securityAnswerHash, loginAttempts, lockoutCount, lockoutTime);
                    return false;
                }
                loginAttempts = 0;
                lockoutCount = 0;
                lockoutTime = 0;
                writeMasterData(masterHash, salt, securityAnswerHash, loginAttempts, lockoutCount, lockoutTime);
                JOptionPane.showMessageDialog(null, "Lockout cleared. You can now try logging in.", "Info", JOptionPane.INFORMATION_MESSAGE);
                return false;
            }
            JOptionPane.showMessageDialog(null, "System locked. Try again in " + (duration - lockoutDuration) + " seconds.", "Error", JOptionPane.ERROR_MESSAGE);
            logger.logActivity("Security", "System locked", "Attempts: " + loginAttempts + ", Remaining: " + (duration - lockoutDuration) + "s");
            return true;
        }

        private boolean isPasswordStrong(String password) {
            if (password.length() < 8 || password.length() > 128) return false;
            boolean hasUpper = false, hasLower = false, hasDigit = false, hasSpecial = false;
            for (char c : password.toCharArray()) {
                if (Character.isUpperCase(c)) hasUpper = true;
                else if (Character.isLowerCase(c)) hasLower = true;
                else if (Character.isDigit(c)) hasDigit = true;
                else if (!Character.isLetterOrDigit(c)) hasSpecial = true;
            }
            return hasUpper && hasLower && hasDigit && hasSpecial;
        }

        private void reEncryptFiles(String newPassword) {
            try {
                if (Files.exists(Paths.get(vaultFile))) {
                    String encryptedData = new String(Files.readAllBytes(Paths.get(vaultFile)));
                    String decryptedData = Encryption.decrypt(encryptedData, masterPassword);
                    String newEncryptedData = Encryption.encrypt(decryptedData, newPassword);
                    Files.write(Paths.get(vaultFile), newEncryptedData.getBytes(), StandardOpenOption.TRUNCATE_EXISTING);
                }

                if (Files.exists(Paths.get(activityLogFile))) {
                    String encryptedData = new String(Files.readAllBytes(Paths.get(activityLogFile)));
                    StringBuilder newEncryptedData = new StringBuilder();
                    String[] segments = encryptedData.split("----ENTRY----");
                    for (int i = 0; i < segments.length; i++) {
                        if (!segments[i].isEmpty()) {
                            String decryptedSegment = Encryption.decrypt(segments[i], masterPassword);
                            if (!decryptedSegment.isEmpty()) {
                                newEncryptedData.append(Encryption.encrypt(decryptedSegment, newPassword));
                                if (i < segments.length - 1) newEncryptedData.append("----ENTRY----");
                            }
                        }
                    }
                    Files.write(Paths.get(activityLogFile), newEncryptedData.toString().getBytes(), StandardOpenOption.TRUNCATE_EXISTING);
                }
            } catch (Exception e) {
                JOptionPane.showMessageDialog(null, "Error re-encrypting files: " + e.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
            }
        }

        public boolean setupMasterPassword(JFrame parent) {
            if (readMasterData() && !masterHash.isEmpty()) {
                JOptionPane.showMessageDialog(parent, "A vault already exists. Please log in or delete data files to reset.", "Error", JOptionPane.ERROR_MESSAGE);
                return false;
            }

            JTextField passwordField = new JPasswordField();
            JTextField confirmField = new JPasswordField();
            Object[] message = {
                "Enter new master password (8+ chars, mixed case, numbers, symbols):", passwordField,
                "Confirm master password:", confirmField
            };
            int option = JOptionPane.showConfirmDialog(parent, message, "Setup Vault", JOptionPane.OK_CANCEL_OPTION);
            if (option != JOptionPane.OK_OPTION) return false;

            String password = new String(((JPasswordField)passwordField).getPassword());
            String confirm = new String(((JPasswordField)confirmField).getPassword());
            if (!password.equals(confirm)) {
                JOptionPane.showMessageDialog(parent, "Passwords do not match.", "Error", JOptionPane.ERROR_MESSAGE);
                return false;
            }
            if (!isPasswordStrong(password)) {
                JOptionPane.showMessageDialog(parent, "Password must be 8-128 chars and include uppercase, lowercase, numbers, and symbols.", "Error", JOptionPane.ERROR_MESSAGE);
                return false;
            }

            try {
                salt = generateSalt();
                masterHash = Encryption.hashPassword(password, salt);
                masterPassword = password;
                logger.setMasterPassword(masterPassword);

                JTextField questionField = new JTextField();
                JTextField answerField = new JPasswordField();
                Object[] qMessage = {
                    "Enter security question:", questionField,
                    "Enter answer:", answerField
                };
                if (JOptionPane.showConfirmDialog(parent, qMessage, "Set Security Question", JOptionPane.OK_CANCEL_OPTION) != JOptionPane.OK_OPTION) {
                    return false;
                }
                securityQuestion = questionField.getText();
                securityAnswerHash = Encryption.hashPassword(new String(((JPasswordField)answerField).getPassword()), salt);
                writeSecurityQuestion(securityQuestion);

                boolean success = writeMasterData(masterHash, salt, securityAnswerHash, 0, 0, 0);
                if (success) {
                    JOptionPane.showMessageDialog(parent, "Vault setup complete.", "Success", JOptionPane.INFORMATION_MESSAGE);
                    logger.logActivity("Action", "Set up new vault", "");
                    return true;
                }
                return false;
            } catch (Exception e) {
                JOptionPane.showMessageDialog(parent, "Error: " + e.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
                return false;
            }
        }

        public boolean login(JFrame parent) {
            if (checkLockout()) return false;
            if (!readMasterData() || masterHash.isEmpty()) {
                JOptionPane.showMessageDialog(parent, "No vault found. Please set up a new vault first.", "Error", JOptionPane.ERROR_MESSAGE);
                return false;
            }

            JPasswordField passwordField = new JPasswordField();
            Object[] message = { "Enter master password:", passwordField };
            int option = JOptionPane.showConfirmDialog(parent, message, "Login", JOptionPane.OK_CANCEL_OPTION);
            if (option != JOptionPane.OK_OPTION) return false;

            String password = new String(passwordField.getPassword());
            if (password.isEmpty()) {
                JOptionPane.showMessageDialog(parent, "Password cannot be empty.", "Error", JOptionPane.ERROR_MESSAGE);
                return false;
            }

            String inputHash = Encryption.hashPassword(password, salt);
            if (!inputHash.equals(masterHash)) {
                loginAttempts++;
                JOptionPane.showMessageDialog(parent, "Incorrect password. Attempts: " + loginAttempts, "Error", JOptionPane.ERROR_MESSAGE);
                logger.logActivity("Action", "Failed login attempt", "Attempt #" + loginAttempts);
                logger.logActivity("Security", "Failed login attempt", "Attempt #" + loginAttempts);
                if (loginAttempts >= 3) {
                    isLocked = true;
                    lockoutTime = System.currentTimeMillis() / 1000;
                    logger.logActivity("Security", "Lockout triggered", "Attempts: " + loginAttempts);
                    JOptionPane.showMessageDialog(parent, "System locked. Try again in " + getLockoutDuration() + " seconds.", "Error", JOptionPane.ERROR_MESSAGE);
                }
                writeMasterData(masterHash, salt, securityAnswerHash, loginAttempts, lockoutCount, lockoutTime);
                try { Thread.sleep(LOGIN_DELAY); } catch (InterruptedException e) {}
                return false;
            }

            loginAttempts = 0;
            lockoutCount = 0;
            lockoutTime = 0;
            writeMasterData(masterHash, salt, securityAnswerHash, loginAttempts, lockoutCount, lockoutTime);
            masterPassword = password;
            logger.setMasterPassword(masterPassword);
            JOptionPane.showMessageDialog(parent, "Authentication successful.", "Success", JOptionPane.INFORMATION_MESSAGE);
            logger.logActivity("Action", "Logged in", "");
            logger.logActivity("Security", "Successful login", "");
            updateLastActivity();
            return true;
        }

        public boolean resetPassword(JFrame parent) {
            if (!readSecurityData() || securityQuestion.isEmpty()) {
                JOptionPane.showMessageDialog(parent, "No security question set. Cannot reset password.", "Error", JOptionPane.ERROR_MESSAGE);
                return false;
            }

            JPasswordField answerField = new JPasswordField();
            Object[] qMessage = { "Security Question: " + securityQuestion, "Enter answer:", answerField };
            if (JOptionPane.showConfirmDialog(parent, qMessage, "Password Reset", JOptionPane.OK_CANCEL_OPTION) != JOptionPane.OK_OPTION) {
                return false;
            }
            String answer = new String(answerField.getPassword());
            if (!Encryption.hashPassword(answer, salt).equals(securityAnswerHash)) {
                JOptionPane.showMessageDialog(parent, "Incorrect answer.", "Error", JOptionPane.ERROR_MESSAGE);
                logger.logActivity("Security", "Failed password reset attempt", "Incorrect answer");
                return false;
            }

            JPasswordField passwordField = new JPasswordField();
            JPasswordField confirmField = new JPasswordField();
            Object[] pMessage = {
                "Enter new master password (8+ chars, mixed case, numbers, symbols):", passwordField,
                "Confirm new master password:", confirmField
            };
            if (JOptionPane.showConfirmDialog(parent, pMessage, "Set New Password", JOptionPane.OK_CANCEL_OPTION) != JOptionPane.OK_OPTION) {
                return false;
            }
            String newPassword = new String(passwordField.getPassword());
            String confirm = new String(confirmField.getPassword());
            if (!newPassword.equals(confirm)) {
                JOptionPane.showMessageDialog(parent, "Passwords do not match.", "Error", JOptionPane.ERROR_MESSAGE);
                return false;
            }
            if (!isPasswordStrong(newPassword)) {
                JOptionPane.showMessageDialog(parent, "Password must be 8-128 chars and include uppercase, lowercase, numbers, and symbols.", "Error", JOptionPane.ERROR_MESSAGE);
                return false;
            }

            try {
                String newSalt = generateSalt();
                String newHash = Encryption.hashPassword(newPassword, newSalt);
                boolean success = writeMasterData(newHash, newSalt, securityAnswerHash, 0, 0, 0);
                reEncryptFiles(newPassword);
                masterPassword = newPassword;
                logger.setMasterPassword(masterPassword);
                if (success) {
                    JOptionPane.showMessageDialog(parent, "Password reset successful.", "Success", JOptionPane.INFORMATION_MESSAGE);
                    logger.logActivity("Action", "Password reset successful", "");
                    logger.logActivity("Security", "Password reset successful", "");
                    return true;
                }
                return false;
            } catch (Exception e) {
                JOptionPane.showMessageDialog(parent, "Error: " + e.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
                return false;
            }
        }

        public boolean changeMasterPassword(JFrame parent) {
            if (checkSessionTimeout(parent)) return false;
            JPasswordField passwordField = new JPasswordField();
            JPasswordField confirmField = new JPasswordField();
            Object[] message = {
                "Enter new master password (8+ chars, mixed case, numbers, symbols):", passwordField,
                "Confirm new master password:", confirmField
            };
            if (JOptionPane.showConfirmDialog(parent, message, "Change Master Password", JOptionPane.OK_CANCEL_OPTION) != JOptionPane.OK_OPTION) {
                return false;
            }
            String newPassword = new String(passwordField.getPassword());
            String confirm = new String(confirmField.getPassword());
            if (!newPassword.equals(confirm)) {
                JOptionPane.showMessageDialog(parent, "Passwords do not match.", "Error", JOptionPane.ERROR_MESSAGE);
                return false;
            }
            if (!isPasswordStrong(newPassword)) {
                JOptionPane.showMessageDialog(parent, "Password must be 8-128 chars and include uppercase, lowercase, numbers, and symbols.", "Error", JOptionPane.ERROR_MESSAGE);
                return false;
            }

            try {
                String newSalt = generateSalt();
                String newHash = Encryption.hashPassword(newPassword, newSalt);
                boolean success = writeMasterData(newHash, newSalt, securityAnswerHash, loginAttempts, lockoutCount, lockoutTime);
                reEncryptFiles(newPassword);
                masterPassword = newPassword;
                logger.setMasterPassword(masterPassword);
                if (success) {
                    JOptionPane.showMessageDialog(parent, "Master password changed successfully.", "Success", JOptionPane.INFORMATION_MESSAGE);
                    logger.logActivity("Action", "Changed master password", "");
                    updateLastActivity();
                    return true;
                }
                return false;
            } catch (Exception e) {
                JOptionPane.showMessageDialog(parent, "Error: " + e.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
                return false;
            }
        }

        public void setSecurityQuestion(JFrame parent) {
            if (checkSessionTimeout(parent)) return;
            JTextField questionField = new JTextField();
            JPasswordField answerField = new JPasswordField();
            Object[] message = {
                "Enter security question:", questionField,
                "Enter answer:", answerField
            };
            if (JOptionPane.showConfirmDialog(parent, message, "Set Security Question", JOptionPane.OK_CANCEL_OPTION) == JOptionPane.OK_OPTION) {
                securityQuestion = questionField.getText();
                securityAnswerHash = Encryption.hashPassword(new String(answerField.getPassword()), salt);
                writeSecurityQuestion(securityQuestion);
                writeMasterData(masterHash, salt, securityAnswerHash, loginAttempts, lockoutCount, lockoutTime);
                JOptionPane.showMessageDialog(parent, "Security question set successfully.", "Success", JOptionPane.INFORMATION_MESSAGE);
                logger.logActivity("Action", "Set security question", "");
            }
        }

        public boolean backupToCloud(JFrame parent) {
            if (!Files.exists(Paths.get(hashFilePath)) || !Files.exists(Paths.get(vaultFile))) {
                JOptionPane.showMessageDialog(parent, "Required vault files not found for backup.", "Error", JOptionPane.ERROR_MESSAGE);
                logger.logActivity("Action", "Cloud Backup Failed", "Required files not found");
                return false;
            }

            int confirm = JOptionPane.showConfirmDialog(parent, "Are you sure you want to backup to cloud?", "Confirm Backup", JOptionPane.YES_NO_OPTION);
            if (confirm != JOptionPane.YES_OPTION) {
                logger.logActivity("Action", "Cloud Backup Cancelled", "User cancelled backup");
                return false;
            }

            try {
                java.util.List<String> command = new ArrayList<>();
                command.add("python");
                command.add("backup.py");
                command.add(hashFilePath);
                command.add(vaultFile);
                command.add(activityLogFile);
                if (Files.exists(Paths.get(QUESTION_FILE))) {
                    command.add(QUESTION_FILE);
                }

                ProcessBuilder pb = new ProcessBuilder(command);
                Process process = pb.start();
                int exitCode = process.waitFor();
                if (exitCode == 0) {
                    JOptionPane.showMessageDialog(parent, "Cloud backup successful.", "Success", JOptionPane.INFORMATION_MESSAGE);
                    logger.logActivity("Action", "Cloud Backup", "Successfully backed up to Google Drive");
                    return true;
                } else {
                    JOptionPane.showMessageDialog(parent, "Cloud backup failed. Ensure Python and backup script are configured correctly.", "Error", JOptionPane.ERROR_MESSAGE);
                    logger.logActivity("Action", "Cloud Backup Failed", "Backup script returned error code: " + exitCode);
                    return false;
                }
            } catch (IOException | InterruptedException e) {
                JOptionPane.showMessageDialog(parent, "Error during cloud backup: " + e.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
                logger.logActivity("Action", "Cloud Backup Failed", e.getMessage());
                return false;
            }
        }

        public boolean checkSessionTimeout(JFrame parent) {
            if (masterPassword != null && !masterPassword.isEmpty() && 
                (System.currentTimeMillis() - lastActivity) / 1000 > config.getSessionTimeout()) {
                JOptionPane.showMessageDialog(parent, "Session timed out due to inactivity.", "Session Timeout", JOptionPane.WARNING_MESSAGE);
                logger.logActivity("Action", "Session timed out", "");
                masterPassword = "";
                return true;
            }
            return false;
        }

        public void updateLastActivity() {
            lastActivity = System.currentTimeMillis();
        }

        public String getMasterPassword() {
            return masterPassword;
        }
    }

    // PasswordManager class (unchanged)
    static class PasswordManager {
        private String vaultFile;
        private java.util.List<Entry> entries;
        private Vault vault;
        private Logger logger;

        public PasswordManager(String vaultFile, Vault vault, Logger logger) {
            this.vaultFile = vaultFile;
            this.vault = vault;
            this.logger = logger;
            this.entries = new ArrayList<>();
            readVault();
        }

        private boolean readVault() {
            entries.clear();
            if (!Files.exists(Paths.get(vaultFile))) return false;
            try {
                String encryptedData = new String(Files.readAllBytes(Paths.get(vaultFile)));
                if (encryptedData.isEmpty()) return false;
                String decryptedData = Encryption.decrypt(encryptedData, vault.getMasterPassword());
                if (decryptedData.isEmpty()) {
                    JOptionPane.showMessageDialog(null, "Decryption failed. Invalid vault file or password.", "Error", JOptionPane.ERROR_MESSAGE);
                    logger.logActivity("Action", "Decrypt Vault Failed", "Invalid vault file or password");
                    return false;
                }
                entries = Arrays.stream(decryptedData.split("\n"))
                        .filter(line -> !line.isEmpty())
                        .map(Entry::deserialize)
                        .collect(Collectors.toList());
                logger.logActivity("Action", "Read Vault", "Successfully loaded vault entries");
                return true;
            } catch (Exception e) {
                JOptionPane.showMessageDialog(null, "Error reading vault: " + e.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
                logger.logActivity("Action", "Read Vault Error", e.getMessage());
                return false;
            }
        }

        private boolean writeVault() {
            try {
                String data = entries.stream().map(Entry::serialize).collect(Collectors.joining("\n"));
                String encryptedData = Encryption.encrypt(data, vault.getMasterPassword());
                Files.write(Paths.get(vaultFile), encryptedData.getBytes(), StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
                logger.logActivity("Action", "Write Vault", "Successfully saved vault entries");
                return true;
            } catch (Exception e) {
                JOptionPane.showMessageDialog(null, "Error writing vault: " + e.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
                logger.logActivity("Action", "Write Vault Error", e.getMessage());
                return false;
            }
        }

        public boolean addEntry(JFrame parent, String website, String username, String password, String category) {
            if (website.isEmpty() || username.isEmpty() || password.isEmpty()) {
                JOptionPane.showMessageDialog(parent, "Website, username, and password cannot be empty.", "Error", JOptionPane.ERROR_MESSAGE);
                logger.logActivity("Action", "Add Entry Failed", "Empty website, username, or password");
                return false;
            }
            if (entries.stream().anyMatch(e -> e.getWebsite().equals(website) && e.getUsername().equals(username) && e.getPassword().equals(password))) {
                JOptionPane.showMessageDialog(parent, "Entry already exists for website: " + website + ", username: " + username, "Error", JOptionPane.ERROR_MESSAGE);
                logger.logActivity("Action", "Add Entry Failed", "Duplicate entry for website: " + website + ", username: " + username);
                return false;
            }
            entries.add(new Entry(website, username, password, category));
            boolean success = writeVault();
            if (success) {
                JOptionPane.showMessageDialog(parent, "Entry added successfully.", "Success", JOptionPane.INFORMATION_MESSAGE);
                logger.logActivity("Action", "Added Entry", "Website: " + website + ", Username: " + username + ", Category: " + category);
            } else {
                JOptionPane.showMessageDialog(parent, "Failed to add entry.", "Error", JOptionPane.ERROR_MESSAGE);
                logger.logActivity("Action", "Add Entry Failed", "Failed to write vault");
            }
            return success;
        }

        public boolean searchEntry(JFrame parent, String website, String username) {
            java.util.List<Entry> matches = entries.stream()
                    .filter(e -> (website.isEmpty() || e.getWebsite().equals(website)) &&
                                 (username.isEmpty() || e.getUsername().equals(username)))
                    .collect(Collectors.toList());
            if (matches.isEmpty()) {
                JOptionPane.showMessageDialog(parent, "No entry found for website: " + website + ", username: " + username, "Info", JOptionPane.INFORMATION_MESSAGE);
                logger.logActivity("Action", "Search Entry", "No entry found for website: " + website + ", username: " + username);
                return false;
            }
            StringBuilder result = new StringBuilder("Matching entries found:\n");
            matches.forEach(e -> result.append("Website: ").append(e.getWebsite()).append("\n")
                                       .append("Username: ").append(e.getUsername()).append("\n")
                                       .append("Password: ").append(e.getPassword()).append("\n")
                                       .append("Category: ").append(e.getCategory()).append("\n--------------------\n"));
            JOptionPane.showMessageDialog(parent, result.toString(), "Search Results", JOptionPane.INFORMATION_MESSAGE);
            logger.logActivity("Action", "Search Entry", "Website: " + website + ", Username: " + username);
            return true;
        }

        public boolean updateEntry(JFrame parent, String website, String username, String password, String category) {
            java.util.List<Entry> matches = entries.stream()
                    .filter(e -> e.getWebsite().equals(website))
                    .collect(Collectors.toList());
            if (matches.isEmpty()) {
                JOptionPane.showMessageDialog(parent, "No entry found to update for website: " + website, "Error", JOptionPane.ERROR_MESSAGE);
                logger.logActivity("Action", "Update Entry Failed", "No entry found for website: " + website);
                return false;
            }

            Entry selected;
            if (matches.size() == 1) {
                selected = matches.get(0);
            } else {
                String[] options = matches.stream()
                        .map(e -> "Username: " + e.getUsername() + ", Category: " + e.getCategory())
                        .toArray(String[]::new);
                int choice = JOptionPane.showOptionDialog(parent, "Select entry to update:", "Multiple Entries Found",
                        JOptionPane.DEFAULT_OPTION, JOptionPane.INFORMATION_MESSAGE, null, options, options[0]);
                if (choice < 0) {
                    logger.logActivity("Action", "Update Entry Failed", "Invalid selection for website: " + website);
                    return false;
                }
                selected = matches.get(choice);
            }

            Entry oldEntry = selected;
            entries.remove(selected);
            entries.add(new Entry(website, username, password, category));
            boolean success = writeVault();
            if (success) {
                JOptionPane.showMessageDialog(parent, "Entry updated successfully.", "Success", JOptionPane.INFORMATION_MESSAGE);
                logger.logActivity("Action", "Updated Entry", "Old: Website: " + oldEntry.getWebsite() +
                        ", Username: " + oldEntry.getUsername() + ", Category: " + oldEntry.getCategory() +
                        " | New: Website: " + website + ", Username: " + username + ", Category: " + category);
            } else {
                JOptionPane.showMessageDialog(parent, "Failed to update entry.", "Error", JOptionPane.ERROR_MESSAGE);
                logger.logActivity("Action", "Update Entry Failed", "Failed to write vault");
            }
            return success;
        }

        public boolean deleteEntry(JFrame parent, String website, String username) {
            java.util.List<Entry> matches = entries.stream()
                    .filter(e -> e.getWebsite().equals(website) && (username.isEmpty() || e.getUsername().equals(username)))
                    .collect(Collectors.toList());
            if (matches.isEmpty()) {
                JOptionPane.showMessageDialog(parent, "No entry found to delete for website: " + website + ", username: " + username, "Error", JOptionPane.ERROR_MESSAGE);
                logger.logActivity("Action", "Delete Entry Failed", "No entry found for website: " + website + ", username: " + username);
                return false;
            }
            matches.forEach(entries::remove);
            boolean success = writeVault();
            if (success) {
                matches.forEach(e -> logger.logActivity("Action", "Deleted Entry", "Website: " + e.getWebsite() +
                        ", Username: " + e.getUsername() + ", Category: " + e.getCategory()));
                JOptionPane.showMessageDialog(parent, "Entry deleted successfully.", "Success", JOptionPane.INFORMATION_MESSAGE);
            } else {
                JOptionPane.showMessageDialog(parent, "Failed to delete entry.", "Error", JOptionPane.ERROR_MESSAGE);
                logger.logActivity("Action", "Delete Entry Failed", "Failed to write vault");
            }
            return success;
        }

        public void listEntries(JFrame parent) {
            if (!readVault()) {
                JOptionPane.showMessageDialog(parent, "Failed to load vault entries. Check master password or vault file.", "Error", JOptionPane.ERROR_MESSAGE);
                logger.logActivity("Action", "List Entries Failed", "Unable to read vault");
                return;
            }

            if (entries.isEmpty()) {
                JOptionPane.showMessageDialog(parent, "No entries in vault.", "Info", JOptionPane.INFORMATION_MESSAGE);
                logger.logActivity("Action", "List Entries", "Vault is empty");
                return;
            }

            StringBuilder result = new StringBuilder();
            Map<String, java.util.List<Entry>> byCategory = entries.stream()
                    .collect(Collectors.groupingBy(e -> e.getCategory() == null || e.getCategory().isEmpty() ? "Uncategorized" : e.getCategory()));
            for (Map.Entry<String, java.util.List<Entry>> entry : byCategory.entrySet()) {
                result.append("Category: ").append(entry.getKey()).append("\n");
                for (Entry e : entry.getValue()) {
                    result.append("Website: ").append(e.getWebsite()).append("\n")
                          .append("Username: ").append(e.getUsername()).append("\n")
                          .append("Password: ").append(e.getPassword()).append("\n\n");
                }
                result.append("----------------------------------------\n");
            }

            JTextArea textArea = new JTextArea(result.toString());
            textArea.setEditable(false);
            textArea.setLineWrap(true);
            textArea.setWrapStyleWord(true);
            JScrollPane scrollPane = new JScrollPane(textArea);
            scrollPane.setPreferredSize(new Dimension(600, 500));

            JOptionPane.showMessageDialog(parent, scrollPane, "Vault Entries (" + entries.size() + ")", JOptionPane.INFORMATION_MESSAGE);
            logger.logActivity("Action", "List Entries", "Displayed all vault entries");
        }

        public boolean copyEntryCredentials(JFrame parent, String website, String username) {
            return false;
        }
    }

    @FunctionalInterface
    interface Consumer<T> {
        void accept(T t);
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> {
            Logger logger = new Logger(ACTIVITY_LOG_FILE);
            Vault vault = new Vault(HASH_FILE, logger, VAULT_FILE, ACTIVITY_LOG_FILE, CONFIG_FILE);
            PasswordManager[] manager = new PasswordManager[1];
            JFrame frame = new JFrame("VaultGuard++");
            frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
            frame.setSize(400, 300);
            frame.setLocationRelativeTo(null);

            showLoginPanel(frame, vault, logger, newPasswordManager -> manager[0] = newPasswordManager);
            frame.setVisible(true);
            logger.logActivity("Action", "Program Start", "VaultGuard++ launched");
        });
    }

    private static ScheduledExecutorService scheduler = null;

    private static void showLoginPanel(JFrame frame, Vault vault, Logger logger, Consumer<PasswordManager> setManager) {
        frame.getContentPane().removeAll();
        if (scheduler != null && !scheduler.isShutdown()) {
            scheduler.shutdownNow();
        }
        JPanel panel = new JPanel(new GridLayout(5, 1, 10, 10));
        panel.setBorder(BorderFactory.createEmptyBorder(20, 20, 20, 20));

        JLabel title = new JLabel("VaultGuard++", SwingConstants.CENTER);
        title.setFont(new Font("Arial", Font.BOLD, 20));
        panel.add(title);

        JButton loginButton = new JButton("Login");
        JButton setupButton = new JButton("Setup New Vault");
        JButton resetButton = new JButton("Forgot Password");
        JButton exitButton = new JButton("Exit");

        loginButton.addActionListener(e -> {
            if (vault.login(frame)) {
                PasswordManager manager = new PasswordManager(VAULT_FILE, vault, logger);
                setManager.accept(manager);
                if (vault.config.getAutoBackup()) {
                    vault.backupToCloud(frame);
                }
                showMainMenu(frame, vault, manager, logger, setManager);
                startSessionTimeout(frame, vault, logger, setManager);
            }
        });
        setupButton.addActionListener(e -> {
            if (vault.setupMasterPassword(frame)) {
                showLoginPanel(frame, vault, logger, setManager);
            }
        });
        resetButton.addActionListener(e -> {
            if (vault.resetPassword(frame)) {
                showLoginPanel(frame, vault, logger, setManager);
            }
        });
        exitButton.addActionListener(e -> {
            logger.logActivity("Action", "Exited application", "");
            if (scheduler != null && !scheduler.isShutdown()) {
                scheduler.shutdownNow();
            }
            System.exit(0);
        });

        panel.add(loginButton);
        panel.add(setupButton);
        panel.add(resetButton);
        panel.add(exitButton);

        frame.add(panel);
        frame.revalidate();
        frame.repaint();
    }

    private static void showMainMenu(JFrame frame, Vault vault, PasswordManager manager, Logger logger, Consumer<PasswordManager> setManager) {
        frame.getContentPane().removeAll();
        JPanel panel = new JPanel(new GridLayout(4, 1, 10, 10));
        panel.setBorder(BorderFactory.createEmptyBorder(20, 20, 20, 20));

        JLabel title = new JLabel("Main Menu", SwingConstants.CENTER);
        title.setFont(new Font("Arial", Font.BOLD, 20));
        panel.add(title);

        JButton passwordManagerButton = new JButton("Password Manager");
        JButton adminPanelButton = new JButton("Admin Panel");
        JButton logoutButton = new JButton("Logout");

        passwordManagerButton.addActionListener(e -> {
            if (!vault.checkSessionTimeout(frame)) {
                showPasswordManagerMenu(frame, vault, manager, logger, setManager);
                logger.logActivity("Action", "Access Password Manager", "User opened password manager");
            } else {
                showLoginPanel(frame, vault, logger, setManager);
            }
        });
        adminPanelButton.addActionListener(e -> {
            if (!vault.checkSessionTimeout(frame)) {
                showAdminPanel(frame, vault, manager, logger, setManager);
                logger.logActivity("Action", "Access Admin Panel", "User opened admin panel");
            } else {
                showLoginPanel(frame, vault, logger, setManager);
            }
        });
        logoutButton.addActionListener(e -> {
            logger.logActivity("Action", "Logged out", "User logged out");
            logger.logActivity("Security", "Logged out", "");
            setManager.accept(null);
            if (scheduler != null && !scheduler.isShutdown()) {
                scheduler.shutdownNow();
            }
            showLoginPanel(frame, vault, logger, setManager);
        });

        panel.add(passwordManagerButton);
        panel.add(adminPanelButton);
        panel.add(logoutButton);

        frame.add(panel);
        frame.revalidate();
        frame.repaint();
    }

    private static void showPasswordManagerMenu(JFrame frame, Vault vault, PasswordManager manager, Logger logger, Consumer<PasswordManager> setManager) {
        frame.getContentPane().removeAll();
        JPanel panel = new JPanel(new GridLayout(8, 1, 10, 10));
        panel.setBorder(BorderFactory.createEmptyBorder(20, 20, 20, 20));

        JLabel title = new JLabel("Password Manager", SwingConstants.CENTER);
        title.setFont(new Font("Arial", Font.BOLD, 20));
        panel.add(title);

        JButton addButton = new JButton("Add Entry");
        JButton searchButton = new JButton("Search Entry");
        JButton updateButton = new JButton("Update Entry");
        JButton deleteButton = new JButton("Delete Entry");
        JButton listButton = new JButton("List All Entries");
        JButton generateButton = new JButton("Generate Password");
        JButton backButton = new JButton("Back");

        addButton.addActionListener(e -> {
            if (!vault.checkSessionTimeout(frame)) {
                JTextField websiteField = new JTextField();
                JTextField usernameField = new JTextField();
                JPasswordField passwordField = new JPasswordField();
                JTextField categoryField = new JTextField();
                Object[] message = {
                    "Website:", websiteField,
                    "Username:", usernameField,
                    "Password:", passwordField,
                    "Category (optional):", categoryField
                };
                if (JOptionPane.showConfirmDialog(frame, message, "Add Entry", JOptionPane.OK_CANCEL_OPTION) == JOptionPane.OK_OPTION) {
                    manager.addEntry(frame, websiteField.getText(), usernameField.getText(),
                            new String(passwordField.getPassword()), categoryField.getText());
                }
                vault.updateLastActivity();
            } else {
                showLoginPanel(frame, vault, logger, setManager);
            }
        });

        searchButton.addActionListener(e -> {
            if (!vault.checkSessionTimeout(frame)) {
                JTextField websiteField = new JTextField();
                JTextField usernameField = new JTextField();
                Object[] message = {
                    "Website (optional):", websiteField,
                    "Username (optional):", usernameField
                };
                if (JOptionPane.showConfirmDialog(frame, message, "Search Entry", JOptionPane.OK_CANCEL_OPTION) == JOptionPane.OK_OPTION) {
                    manager.searchEntry(frame, websiteField.getText(), usernameField.getText());
                }
                vault.updateLastActivity();
            } else {
                showLoginPanel(frame, vault, logger, setManager);
            }
        });

        updateButton.addActionListener(e -> {
            if (!vault.checkSessionTimeout(frame)) {
                JTextField websiteField = new JTextField();
                JTextField usernameField = new JTextField();
                JPasswordField passwordField = new JPasswordField();
                JTextField categoryField = new JTextField();
                Object[] message = {
                    "Website:", websiteField,
                    "New Username:", usernameField,
                    "New Password:", passwordField,
                    "New Category (optional):", categoryField
                };
                if (JOptionPane.showConfirmDialog(frame, message, "Update Entry", JOptionPane.OK_CANCEL_OPTION) == JOptionPane.OK_OPTION) {
                    manager.updateEntry(frame, websiteField.getText(), usernameField.getText(),
                            new String(passwordField.getPassword()), categoryField.getText());
                }
                vault.updateLastActivity();
            } else {
                showLoginPanel(frame, vault, logger, setManager);
            }
        });

        deleteButton.addActionListener(e -> {
            if (!vault.checkSessionTimeout(frame)) {
                JTextField websiteField = new JTextField();
                JTextField usernameField = new JTextField();
                Object[] message = {
                    "Website:", websiteField,
                    "Username (optional):", usernameField
                };
                if (JOptionPane.showConfirmDialog(frame, message, "Delete Entry", JOptionPane.OK_CANCEL_OPTION) == JOptionPane.OK_OPTION) {
                    manager.deleteEntry(frame, websiteField.getText(), usernameField.getText());
                }
                vault.updateLastActivity();
            } else {
                showLoginPanel(frame, vault, logger, setManager);
            }
        });

        listButton.addActionListener(e -> {
            if (!vault.checkSessionTimeout(frame)) {
                manager.listEntries(frame);
                vault.updateLastActivity();
            } else {
                showLoginPanel(frame, vault, logger, setManager);
            }
        });

        generateButton.addActionListener(e -> {
            if (!vault.checkSessionTimeout(frame)) {
                JTextField websiteField = new JTextField();
                JTextField usernameField = new JTextField();
                JTextField categoryField = new JTextField();
                JTextField lengthField = new JTextField("12");
                JCheckBox upperCheck = new JCheckBox("Uppercase letters", true);
                JCheckBox lowerCheck = new JCheckBox("Lowercase letters", true);
                JCheckBox digitsCheck = new JCheckBox("Digits", true);
                JCheckBox specialCheck = new JCheckBox("Special characters", true);
                Object[] message = {
                    "Website:", websiteField,
                    "Username:", usernameField,
                    "Category (optional):", categoryField,
                    "Password length (8-128):", lengthField,
                    upperCheck, lowerCheck, digitsCheck, specialCheck
                };
                if (JOptionPane.showConfirmDialog(frame, message, "Generate Password", JOptionPane.OK_CANCEL_OPTION) == JOptionPane.OK_OPTION) {
                    try {
                        int length = Integer.parseInt(lengthField.getText());
                        String password = PasswordGenerator.generatePassword(length, upperCheck.isSelected(),
                                lowerCheck.isSelected(), digitsCheck.isSelected(), specialCheck.isSelected());
                        if (password.isEmpty()) {
                            JOptionPane.showMessageDialog(frame, "Invalid length or no character types selected.", "Error", JOptionPane.ERROR_MESSAGE);
                            logger.logActivity("Action", "Generate Password Failed", "Invalid parameters");
                        } else {
                            JOptionPane.showMessageDialog(frame, "Generated password: " + password, "Generated Password", JOptionPane.INFORMATION_MESSAGE);
                            int addChoice = JOptionPane.showConfirmDialog(frame, "Add this password as an entry?", "Confirm", JOptionPane.YES_NO_OPTION);
                            if (addChoice == JOptionPane.YES_OPTION) {
                                manager.addEntry(frame, websiteField.getText(), usernameField.getText(), password, categoryField.getText());
                            } else {
                                logger.logActivity("Action", "Generate Password", "Generated password not saved");
                            }
                        }
                    } catch (NumberFormatException ex) {
                        JOptionPane.showMessageDialog(frame, "Invalid length.", "Error", JOptionPane.ERROR_MESSAGE);
                        logger.logActivity("Action", "Generate Password Failed", "Invalid length");
                    }
                    vault.updateLastActivity();
                }
            } else {
                showLoginPanel(frame, vault, logger, setManager);
            }
        });

        backButton.addActionListener(e -> {
            if (!vault.checkSessionTimeout(frame)) {
                logger.logActivity("Action", "Exit Password Manager", "Returned to main menu");
                showMainMenu(frame, vault, manager, logger, setManager);
            } else {
                showLoginPanel(frame, vault, logger, setManager);
            }
        });

        panel.add(addButton);
        panel.add(searchButton);
        panel.add(updateButton);
        panel.add(deleteButton);
        panel.add(listButton);
        panel.add(generateButton);
        panel.add(backButton);

        frame.add(panel);
        frame.revalidate();
        frame.repaint();
    }

    private static void showAdminPanel(JFrame frame, Vault vault, PasswordManager manager, Logger logger, Consumer<PasswordManager> setManager) {
        frame.getContentPane().removeAll();
        JPanel panel = new JPanel(new GridLayout(9, 1, 10, 10));
        panel.setBorder(BorderFactory.createEmptyBorder(20, 20, 20, 20));

        JLabel title = new JLabel("Admin Panel", SwingConstants.CENTER);
        title.setFont(new Font("Arial", Font.BOLD, 20));
        panel.add(title);

        JButton changePasswordButton = new JButton("Change Master Password");
        JButton setQuestionButton = new JButton("Set Security Question");
        JButton clearLogsButton = new JButton("Clear Logs");
        JButton viewLogsButton = new JButton("View Activity Log");
        JButton backupButton = new JButton("Backup to Cloud");
        JButton toggleAutoBackupButton = new JButton("Toggle Auto Backup");
        JButton backButton = new JButton("Back");

        changePasswordButton.addActionListener(e -> {
            if (!vault.checkSessionTimeout(frame)) {
                vault.changeMasterPassword(frame);
                vault.updateLastActivity();
            } else {
                showLoginPanel(frame, vault, logger, setManager);
            }
        });

        setQuestionButton.addActionListener(e -> {
            if (!vault.checkSessionTimeout(frame)) {
                vault.setSecurityQuestion(frame);
                vault.updateLastActivity();
            } else {
                showLoginPanel(frame, vault, logger, setManager);
            }
        });

        clearLogsButton.addActionListener(e -> {
            if (!vault.checkSessionTimeout(frame)) {
                logger.clearLog();
                JOptionPane.showMessageDialog(frame, "All logs cleared successfully.", "Success", JOptionPane.INFORMATION_MESSAGE);
                vault.updateLastActivity();
            } else {
                showLoginPanel(frame, vault, logger, setManager);
            }
        });

        viewLogsButton.addActionListener(e -> {
            if (!vault.checkSessionTimeout(frame)) {
                JTextArea textArea = new JTextArea(logger.getActivityLog());
                textArea.setEditable(false);
                textArea.setLineWrap(true);
                JScrollPane scrollPane = new JScrollPane(textArea);
                scrollPane.setPreferredSize(new Dimension(400, 300));
                JOptionPane.showMessageDialog(frame, scrollPane, "Activity Log", JOptionPane.INFORMATION_MESSAGE);
                vault.updateLastActivity();
            } else {
                showLoginPanel(frame, vault, logger, setManager);
            }
        });

        backupButton.addActionListener(e -> {
            if (!vault.checkSessionTimeout(frame)) {
                vault.backupToCloud(frame);
                vault.updateLastActivity();
            } else {
                showLoginPanel(frame, vault, logger, setManager);
            }
        });

        toggleAutoBackupButton.addActionListener(e -> {
            if (!vault.checkSessionTimeout(frame)) {
                boolean newState = !vault.config.getAutoBackup();
                vault.config.setAutoBackup(newState);
                JOptionPane.showMessageDialog(frame, "Auto Backup " + (newState ? "enabled" : "disabled") + ".", "Success", JOptionPane.INFORMATION_MESSAGE);
                logger.logActivity("Action", "Toggled Auto Backup", "Set to " + newState);
                vault.updateLastActivity();
            } else {
                showLoginPanel(frame, vault, logger, setManager);
            }
        });

        backButton.addActionListener(e -> {
            if (!vault.checkSessionTimeout(frame)) {
                logger.logActivity("Action", "Exit Admin Panel", "Returned to main menu");
                showMainMenu(frame, vault, manager, logger, setManager);
            } else {
                showLoginPanel(frame, vault, logger, setManager);
            }
        });

        panel.add(changePasswordButton);
        panel.add(setQuestionButton);
        panel.add(clearLogsButton);
        panel.add(viewLogsButton);
        panel.add(backupButton);
        panel.add(toggleAutoBackupButton);
        panel.add(backButton);

        frame.add(panel);
        frame.revalidate();
        frame.repaint();
    }

    private static void startSessionTimeout(JFrame frame, Vault vault, Logger logger, Consumer<PasswordManager> setManager) {
        if (scheduler != null && !scheduler.isShutdown()) {
            scheduler.shutdownNow();
        }
        scheduler = Executors.newScheduledThreadPool(1);
        scheduler.scheduleAtFixedRate(() -> {
            if (vault.checkSessionTimeout(frame)) {
                SwingUtilities.invokeLater(() -> {
                    logger.logActivity("Action", "Session Timeout", "Automatic logout due to inactivity");
                    setManager.accept(null);
                    showLoginPanel(frame, vault, logger, setManager);
                });
                scheduler.shutdownNow();
            }
        }, 0, 10, TimeUnit.SECONDS);
    }
}
