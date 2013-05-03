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
package org.xwiki.contrib.encryption;

import org.xwiki.component.annotation.ComponentRole;
import org.xwiki.contrib.encryption.internal.DefaultEncryptionTool;

/**
 * Interface (aka Role) of the Component
 */
@ComponentRole
public interface EncryptionTool
{
    /**
     * Encrypt a text.
     *
     * @return an encrypted text
     */
    String encrypt(String clearText) ;
    
    /**
     * Display an encrypted text if the user can see it.
     * 
     * @param encryptedText Text to be decrypted
     * @param editRight True if the user is allowed to see this
     * @return Decrypted text if the user is allowed to do it
     */
    String display(String encryptedText, boolean editRight);
    
    /**
     * Check user rights.
     * 
     * @return true if the current user can decrypt a text.
     */
    boolean hasDecryptionRight();
}

