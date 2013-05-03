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

import org.xwiki.component.annotation.Component;
import org.xwiki.contrib.encryption.EncryptionTool;
import org.xwiki.script.service.ScriptService;


import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Singleton;

/**
 * Make the Encryption Tool API available to scripting.
 */
@Component
@Named("encryptionTool")
@Singleton
public class EncryptionToolScriptService implements ScriptService
{
    @Inject
    private EncryptionTool encryptionTool;
    
    public String encrypt (String clearText)
    {
        return this.encryptionTool.encrypt(clearText);
    }
    
    public String display (String encryptedText)
    {
        return this.encryptionTool.display(encryptedText, this.encryptionTool.hasDecryptionRight());
    }
    
    public boolean hasDecryptionRight()
    {
        return this.encryptionTool.hasDecryptionRight();
    }
}
