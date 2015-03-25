/*
 * See the NOTICE file distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */
package org.xwiki.contrib.encryption.internal;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.KeyStore;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.inject.Inject;
import javax.inject.Singleton;

import org.apache.commons.codec.binary.Base64;
import org.slf4j.Logger;
import org.xwiki.bridge.DocumentAccessBridge;
import org.xwiki.component.annotation.Component;
import org.xwiki.context.Execution;
import org.xwiki.context.ExecutionContext;
import org.xwiki.contrib.encryption.EncryptionTool;
import org.xwiki.environment.Environment;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.model.reference.DocumentReferenceResolver;
import org.xwiki.model.reference.EntityReferenceSerializer;
import org.xwiki.security.authorization.AuthorizationManager;

import com.xpn.xwiki.XWikiContext;

/**
 * Implementation of a <tt>Encryption Tool</tt> component.
 */
@Component
@Singleton
public class DefaultEncryptionTool implements EncryptionTool
{
    /** The file where we store the encryption key. */
    private static final String ENCRYPTION_FILE_NAME = "EncryptionToolKey.txt";

    private static final String KEYSTORE_PASSWORD = "";

    private static final String ENCRYPTION_KEY_PROTECTION = "";

    @Inject
    private Environment environment;

    @Inject
    private Logger logger;

    /** Provides access to documents. Injected by the Component Manager. */
    @Inject
    private DocumentAccessBridge documentAccessBridge;

    @Inject
    private DocumentReferenceResolver<String> resolver;

    /** Provides access to the request context. Injected by the Component Manager. */
    @Inject
    private Execution execution;

    /**
     * Reference string serializer.
     */
    @Inject
    protected EntityReferenceSerializer<String> stringSerializer;

    @Override
    public String encrypt(String clearText)
    {
        try {
            logger.debug("Encrypt started");
            Cipher c1 = Cipher.getInstance("AES");
            SecretKeySpec key = this.getKey();
            c1.init(Cipher.ENCRYPT_MODE, key);
            byte[] clearTextBytes;
            clearTextBytes = clearText.getBytes();
            byte[] encryptedText = c1.doFinal(clearTextBytes);
            return new String(Base64.encodeBase64(encryptedText));
        } catch (Exception e) {
            logger.warn("Exception encountered while trying to perform encryption : " + e.getMessage());
            return null;
        }
    }

    private String decrypt(String encryptedText)
    {
        try {
            logger.debug("Decrypt started");
            byte[] decodedEncryptedText =
                Base64.decodeBase64(encryptedText.replaceAll("_", "=").getBytes("ISO-8859-1"));
            Cipher c1 = Cipher.getInstance("AES");
            SecretKeySpec key = this.getKey();
            c1.init(Cipher.DECRYPT_MODE, key);
            byte[] decryptedText = c1.doFinal(decodedEncryptedText);
            String decryptedTextString = new String(decryptedText);
            return decryptedTextString;
        } catch (Exception e) {
            logger.warn("Exception encountered while trying to perform decryption : " + e.getMessage());
            return null;
        }
    }

    @Override
    public String display(String encryptedText, boolean viewRight)
    {
        if (viewRight)
            return decrypt(encryptedText);
        else
            return null;
    }

    @Override
    public boolean hasDecryptionRight()
    {
        boolean result = false;
        try {
            ExecutionContext context = this.execution.getContext();
            XWikiContext xwikiContext = (XWikiContext) context.getProperty("xwikicontext");
            DocumentReference userRef = this.documentAccessBridge.getCurrentUserReference();
            logger.debug("Proper wiki : "
                + documentAccessBridge.getCurrentDocumentReference().getWikiReference().toString());
            String wiki = documentAccessBridge.getCurrentDocumentReference().getWikiReference().getName();
            logger.debug("WikiName : " + wiki);
            if (xwikiContext.getWiki().getRightService()
                .hasAccessLevel("admin", stringSerializer.serialize(userRef), "XWiki.XWikiPreferences", xwikiContext)) {
                logger.debug("Current user has programming rights on this wiki.");
                result = true;
                return result;
            }
            String adminPage = wiki + ":Encryption.Administration";
            DocumentReference docRef = resolver.resolve(adminPage);
            String rightsClass = wiki + ":Encryption.DecryptionRightClass";
            DocumentReference classRef = resolver.resolve(rightsClass);

            /**
             * Content example of the currentUser: xwiki:XWiki.username
             */
            String currentUser = userRef.toString();

            int nb = this.documentAccessBridge.getObjectNumber(docRef, classRef, "type", "Wiki");
            if (nb >= 0) {
                Object authorizedUsers = this.documentAccessBridge.getProperty(docRef, classRef, nb, "authorizedUsers");
                String[] users = authorizedUsers.toString().split(",");
                if (hashDecryptionRights(currentUser, users)) {
                    logger.debug("Current user has decryption rights on the whole wiki");
                    result = true;
                    return result;
                }
            }
            /* Now let's check rights on spaces */
            String space =
                this.documentAccessBridge.getCurrentDocumentReference().getSpaceReferences().get(0).getName();
            nb = this.documentAccessBridge.getObjectNumber(docRef, classRef, "name", space);
            if (nb >= 0) {
                Object authorizedUsersSpace =
                    this.documentAccessBridge.getProperty(docRef, classRef, nb, "authorizedUsers");
                String[] users = authorizedUsersSpace.toString().split(",");
                if (hashDecryptionRights(currentUser, users)) {
                    logger.debug("Current user has decryption rights on this space");
                    result = true;
                    return result;
                }
            }
            String page = this.documentAccessBridge.getCurrentDocumentReference().getName();
            page = space + "." + page;
            nb = this.documentAccessBridge.getObjectNumber(docRef, classRef, "name", page);
            if (nb >= 0) {
                logger.debug("Object found");
                Object authorizedUsersPage =
                    this.documentAccessBridge.getProperty(docRef, classRef, nb, "authorizedUsers");
                logger.debug("Authorized users : " + authorizedUsersPage.toString());

                String[] users = authorizedUsersPage.toString().split(",");
                if (hashDecryptionRights(currentUser, users)) {
                    logger.debug("Current user has decryption rights on this page");
                    result = true;
                    return result;
                }
            }
            result = false;
            return result;
        } catch (Exception e) {
            logger.warn("Unable to verify decryption rights");
            result = false;
            return result;
        }
    }

    /**
     * @param currentUser
     * @param decryptionRightUsers
     * @return true if the current user name equals one of the decryption right users.
     */
    private boolean hashDecryptionRights(String currentUser, String[] decryptionRightUsers)
    {
        boolean result = false;

        currentUser = currentUser.substring(currentUser.lastIndexOf(".") + 1);
        for (String tmpUser : decryptionRightUsers) {
            tmpUser = tmpUser.substring(tmpUser.lastIndexOf(".") + 1);
            if (currentUser.equalsIgnoreCase(tmpUser)) {
                result = true;
            }
        }

        return result;
    }

    private SecretKeySpec generateRandomKey()
    {
        try {
            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
            keyGenerator.init(128);
            SecretKey key = keyGenerator.generateKey();
            return (SecretKeySpec) key;
        } catch (Exception e) {
            logger.warn("Exception encountered while generating the encryption key : " + e.getMessage());
            return null;
        }
    }

    private SecretKeySpec getKey()
    {
        try {
            KeyStore ks = KeyStore.getInstance("JCEKS");
            char[] password = KEYSTORE_PASSWORD.toCharArray();
            File file = this.getEncryptionFile();
            if (!file.exists()) {
                logger.warn("The encryption file doesn't exist yet");
                ks = initiateStore(ks, password, file);
            } else
                ks.load(new FileInputStream(file), password);
            return retrieveEncryptionKey(ks);
        } catch (Exception e) {
            logger.warn("Cannot retrieve encryption key : " + e.getMessage());
            return null;
        }
    }

    /**
     * @param ks Keystore
     * @param password Password of the keystore
     * @param file File where the keystore is
     * @return The keystore initiated
     * @throws Exception
     */
    private synchronized KeyStore initiateStore(KeyStore ks, char[] password, File file) throws Exception
    {
        if (file.exists()) {
            // If the file already exists, it means another thread created it in the meanwhile
            ks.load(new FileInputStream(file), password);
            return ks;
        }
        logger.debug("The encryption file doesn't exist yet");
        ks.load(null, password);
        storeEncryptionKey(ks);
        return ks;
    }

    /**
     * Get the file where the encryptionKey is supposed to be stored.
     * 
     * @return The file where the key is to be stored.
     */
    private File getEncryptionFile()
    {
        File permDir = environment.getPermanentDirectory();
        String path = permDir.getAbsolutePath() + File.separator + ENCRYPTION_FILE_NAME;
        File encryptionFile = new File(path);
        return encryptionFile;
    }

    /**
     * Store the encryption key.
     * 
     * @param ks Keystore where the key should be stored
     */
    private void storeEncryptionKey(KeyStore ks)
    {
        try {
            logger.debug("Start storing password");
            String storePassword = KEYSTORE_PASSWORD;
            String protection = ENCRYPTION_KEY_PROTECTION;
            SecretKeySpec key = generateRandomKey();
            logger.debug("Encryption key generated : " + key);
            KeyStore.SecretKeyEntry skEntry = new KeyStore.SecretKeyEntry(key);
            ks.setEntry("encryptionKey", skEntry, new KeyStore.PasswordProtection(protection.toCharArray()));
            File file = this.getEncryptionFile();
            if (!file.exists()) {
                file.createNewFile();
            }
            FileOutputStream fos = new FileOutputStream(file);
            ks.store(fos, storePassword.toCharArray());
            logger.debug("Finish storing encryption key");
        } catch (Exception e) {
            logger.warn("Exception encountered while trying to store the key : " + e.getMessage());
        }
    }

    private SecretKeySpec retrieveEncryptionKey(KeyStore ks)
    {
        String protection = ENCRYPTION_KEY_PROTECTION;
        try {
            logger.debug("Start retrieving password");
            KeyStore.SecretKeyEntry pkEntry =
                (KeyStore.SecretKeyEntry) ks.getEntry("encryptionKey",
                    new KeyStore.PasswordProtection(protection.toCharArray()));
            SecretKeySpec mySecretKey = (SecretKeySpec) pkEntry.getSecretKey();
            return mySecretKey;
        } catch (Exception e) {
            logger.warn("Exception encountered while trying to retrieve the password : " + e.getMessage());
            return null;
        }
    }

}
